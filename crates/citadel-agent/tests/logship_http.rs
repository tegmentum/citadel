//! Log-shipping over the real HTTP transport: events appended to one agent
//! replicate to its peers via gossiped LtHash digests and pulls — proving the
//! same node logic the deterministic harness exercises also runs over sockets.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use citadel_agent::http::{router, HttpTransport};
use citadel_agent::{build_node, peer_id, peer_public_key, spawn_node, AgentHandle};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

const EPOCH: u64 = 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_replicates_to_peers_over_http() {
    let mesh_id = MeshId::new("logship-http-mesh");
    let seeds = [1u8, 2, 3];

    // Bind ephemeral ports so peers can address each other.
    let mut listeners = Vec::new();
    let mut urls: HashMap<u8, String> = HashMap::new();
    for &s in &seeds {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.insert(s, format!("http://{}", l.local_addr().unwrap()));
        listeners.push((s, l));
    }

    let roster: Vec<(NodeId, _)> = seeds
        .iter()
        .map(|s| (peer_id(&mesh_id, EPOCH, *s), peer_public_key(*s)))
        .collect();
    let cfg = NodeConfig {
        mesh_epoch: EPOCH,
        witness_count: 0,
        probe_interval: 1,
        log_window_size: 8,
        log_advertise_interval: 2,
        ..NodeConfig::default()
    };

    let mut handles: HashMap<u8, AgentHandle> = HashMap::new();
    for (s, listener) in listeners {
        let url_map: HashMap<NodeId, String> = seeds
            .iter()
            .filter(|p| **p != s)
            .map(|p| (peer_id(&mesh_id, EPOCH, *p), urls[p].clone()))
            .collect();
        let (node, _id) = build_node(&mesh_id, s, "worker", cfg.clone(), &roster);
        let handle = spawn_node(
            node,
            Arc::new(HttpTransport::new(url_map)),
            Duration::from_millis(40),
        );
        let app = router(handle.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        handles.insert(s, handle);
    }

    // The origin (seed 1) records a run of measurement events.
    let origin = &handles[&1];
    for i in 0..20u8 {
        origin.append_event([i; 32]).await;
    }
    let origin_id = peer_id(&mesh_id, EPOCH, 1).to_hex();
    let origin_root = origin.log_state().await.own_root;
    assert!(!origin_root.is_empty());

    // The peers should converge on a faithful replica of the origin's log.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut replicated = false;
    while Instant::now() < deadline {
        let mut all = true;
        for s in [2u8, 3] {
            let st = handles[&s].log_state().await;
            if st.replicas.get(&origin_id) != Some(&origin_root) {
                all = false;
                break;
            }
        }
        if all {
            replicated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        replicated,
        "peers should replicate the origin's log over HTTP"
    );
}
