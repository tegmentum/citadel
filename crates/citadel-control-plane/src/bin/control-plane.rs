//! The Citadel control-plane server: serves the agreement-first dashboard + JSON
//! API (CP1–CP6) over a chosen durable store. Run **N replicas behind a load
//! balancer over one shared `PgStore`** for the horizontally-scaled read API
//! (CP7); set the shard env to make this instance a CP7 ingestion shard.
//!
//! Config (env):
//! * `CITADEL_CP_ADDR`        — bind address (default `127.0.0.1:8088`)
//! * `CITADEL_CP_STORE`       — `mem` | `redb` | `pg` (default `mem`)
//! * `CITADEL_CP_REDB_PATH`   — redb file (default `control-plane.redb`)
//! * `CITADEL_PG_URL`         — Postgres URL (requires the `postgres-store` build)
//! * `CITADEL_CP_SHARD_ID`    — this shard's observer node id (hex); unset = own all
//! * `CITADEL_CP_SHARDS`      — comma-separated shard ids (hex), including self
//! * `CITADEL_CP_REPLICATION` — shards per subject (default `1`)
//!
//! Ingestion (an observer `Node` feeding `ControlPlane::observe` + the write-relay
//! loop) is run by the agent in observer mode writing to the same shared store;
//! see `docs/deploy/control-plane.md`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use citadel_control_plane::shard::ShardId;
use citadel_control_plane::{api, ControlPlane, ControlPlaneStore, MemStore, RedbStore};
use citadel_mesh::NodeId;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse the optional CP7 shard identity from the environment.
fn shard_from_env() -> anyhow::Result<Option<(ShardId, Vec<ShardId>, usize)>> {
    let Ok(me_hex) = std::env::var("CITADEL_CP_SHARD_ID") else {
        return Ok(None); // un-sharded: this CP owns the whole subject space
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

async fn serve<S: ControlPlaneStore + 'static>(
    store: S,
    addr: SocketAddr,
    shard: Option<(ShardId, Vec<ShardId>, usize)>,
) -> anyhow::Result<()> {
    let mut cp = ControlPlane::new(store);
    if let Some((me, shards, replication)) = shard {
        cp.set_shard(me, shards, replication);
    }
    let shared = Arc::new(Mutex::new(cp));
    println!("citadel control plane: dashboard + API on http://{addr}");
    api::serve(addr, shared).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = env_or("CITADEL_CP_ADDR", "127.0.0.1:8088").parse()?;
    let shard = shard_from_env()?;
    match env_or("CITADEL_CP_STORE", "mem").as_str() {
        "mem" => serve(MemStore::new(), addr, shard).await,
        "redb" => {
            let path = env_or("CITADEL_CP_REDB_PATH", "control-plane.redb");
            serve(RedbStore::open(path)?, addr, shard).await
        }
        #[cfg(feature = "postgres-store")]
        "pg" => {
            let url = std::env::var("CITADEL_PG_URL")
                .map_err(|_| anyhow::anyhow!("CITADEL_PG_URL required for the pg store"))?;
            serve(citadel_control_plane::PgStore::connect(&url)?, addr, shard).await
        }
        other => anyhow::bail!("unknown CITADEL_CP_STORE '{other}' (mem|redb|pg)"),
    }
}
