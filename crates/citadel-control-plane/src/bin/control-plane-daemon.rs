//! The combined CP7 observer-ingestion daemon: runs a non-voting **observer
//! node** in the mesh (over the agent's HTTP / mutual-TLS transport, with the
//! agent's TPM backend), feeds its verified gossip into a [`ControlPlane`], and
//! serves the dashboard + API — one process that both ingests and serves.
//! Requires the `daemon` feature.
//!
//! Config (env): `CITADEL_MESH`, `CITADEL_SEED`, `CITADEL_PEERS`
//! (`[[seed,"url"],…]`), `CITADEL_MESH_LISTEN` (inbound gossip, default
//! `0.0.0.0:8090`), `CITADEL_CP_ADDR` (dashboard/API, default `0.0.0.0:8088`),
//! `CITADEL_WITNESS_COUNT`, `CITADEL_TICK_MS`; the TPM backend
//! (`CITADEL_TPM_BACKEND` + `CITADEL_PEER_CERTS` for mutual TLS) is selected
//! exactly as for `citadel-agent`; plus the store + shard vars (see
//! `docs/deploy/control-plane.md`). With a real backend + peer certs the observer
//! runs mutual TLS; otherwise plain HTTP with the mock backend.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use citadel_agent::http::{mtls_client, router, serve_mtls, HttpTransport};
use citadel_agent::{
    build_node_with_backend, make_backend, mint_tls_identity, parse_peer_certs, peer_id,
    peer_public_key, spawn_node, AgentHandle, Transport,
};
use citadel_control_plane::daemon::run_observer_daemon;
use citadel_control_plane::shard::ShardId;
use citadel_control_plane::{api, ControlPlane, ControlPlaneStore, MemStore, RedbStore};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn shard_from_env() -> anyhow::Result<Option<(ShardId, Vec<ShardId>, usize)>> {
    let Ok(me_hex) = std::env::var("CITADEL_CP_SHARD_ID") else {
        return Ok(None);
    };
    let me = NodeId::from_hex(&me_hex).ok_or_else(|| anyhow::anyhow!("bad CITADEL_CP_SHARD_ID"))?;
    let shards = std::env::var("CITADEL_CP_SHARDS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    NodeId::from_hex(p.trim()).ok_or_else(|| anyhow::anyhow!("bad shard id {p}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_else(|| vec![me]);
    let replication = env_or("CITADEL_CP_REPLICATION", "1").parse().unwrap_or(1);
    Ok(Some((me, shards, replication)))
}

async fn run<S: ControlPlaneStore + 'static>(
    store: S,
    cp_addr: SocketAddr,
    observer: AgentHandle,
) -> anyhow::Result<()> {
    let mut cp = ControlPlane::new(store);
    if let Some((me, shards, replication)) = shard_from_env()? {
        cp.set_shard(me, shards, replication);
    }
    let cp = Arc::new(Mutex::new(cp));
    // Ingest the observer's verified feed + relay operator writes, forever.
    tokio::spawn(run_observer_daemon(
        cp.clone(),
        observer,
        Duration::from_secs(2),
    ));
    println!("citadel control-plane daemon: dashboard + API on http://{cp_addr}");
    api::serve(cp_addr, cp).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mesh_id = MeshId::new(env_or("CITADEL_MESH", "citadel"));
    let epoch = 1u64;
    let seed: u8 = env_or("CITADEL_SEED", "9").parse()?;
    let peers_cfg: Vec<(u8, String)> = serde_json::from_str(&env_or("CITADEL_PEERS", "[]"))?;
    let mesh_addr: SocketAddr = env_or("CITADEL_MESH_LISTEN", "0.0.0.0:8090").parse()?;
    let cp_addr: SocketAddr = env_or("CITADEL_CP_ADDR", "0.0.0.0:8088").parse()?;
    let witness_count = env_or("CITADEL_WITNESS_COUNT", "3").parse().unwrap_or(3);
    let tick_ms = env_or("CITADEL_TICK_MS", "200").parse().unwrap_or(200);

    let config = NodeConfig {
        mesh_epoch: epoch,
        observer: true,
        witness_count,
        ..NodeConfig::default()
    };
    let peers: Vec<(NodeId, _)> = peers_cfg
        .iter()
        .map(|(s, _)| (peer_id(&mesh_id, epoch, *s), peer_public_key(*s)))
        .collect();
    let url_map: HashMap<NodeId, String> = peers_cfg
        .iter()
        .map(|(s, url)| (peer_id(&mesh_id, epoch, *s), url.clone()))
        .collect();

    // The observer node, with the agent's selected TPM backend, joining the mesh
    // exactly like a worker but non-voting (it ships no evidence of its own).
    let (mut node, id) = build_node_with_backend(
        &mesh_id,
        seed,
        "control-plane",
        config,
        &peers,
        make_backend(),
    );

    // Mutual TLS (E2) when a real backend can mint a cert + peers are pinned.
    let tls_identity = mint_tls_identity(&mut node, &id.to_string());
    let peer_certs = parse_peer_certs(&mesh_id, epoch);
    let mtls = tls_identity.filter(|_| !peer_certs.is_empty());

    let transport: Arc<dyn Transport> = match &mtls {
        Some(identity) => {
            println!("citadel control-plane daemon: mutual-TLS observer on {mesh_addr}");
            Arc::new(HttpTransport::with_client(
                url_map,
                mtls_client(identity, peer_certs.clone())?,
            ))
        }
        None => {
            println!("citadel control-plane daemon: plain-HTTP observer on {mesh_addr}");
            Arc::new(HttpTransport::new(url_map))
        }
    };
    let observer = spawn_node(node, transport, Duration::from_millis(tick_ms));

    // Serve the observer's inbound gossip endpoint (peers reach it here).
    let gossip_app = router(observer.clone());
    match mtls {
        Some(identity) => {
            let pc = peer_certs.clone();
            tokio::spawn(async move {
                let _ = serve_mtls(gossip_app, mesh_addr, &identity, pc).await;
            });
        }
        None => {
            let listener = tokio::net::TcpListener::bind(mesh_addr).await?;
            tokio::spawn(async move {
                let _ = axum::serve(listener, gossip_app).await;
            });
        }
    }

    match env_or("CITADEL_CP_STORE", "mem").as_str() {
        "mem" => run(MemStore::new(), cp_addr, observer).await,
        "redb" => {
            let path = env_or("CITADEL_CP_REDB_PATH", "control-plane.redb");
            run(RedbStore::open(path)?, cp_addr, observer).await
        }
        #[cfg(feature = "postgres-store")]
        "pg" => {
            let url = std::env::var("CITADEL_PG_URL")
                .map_err(|_| anyhow::anyhow!("CITADEL_PG_URL required for the pg store"))?;
            run(
                citadel_control_plane::PgStore::connect(&url)?,
                cp_addr,
                observer,
            )
            .await
        }
        other => anyhow::bail!("unknown CITADEL_CP_STORE '{other}' (mem|redb|pg)"),
    }
}
