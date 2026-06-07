//! Smoke test for the HTTP transport: three agents on ephemeral localhost
//! ports gossip over real sockets and converge on membership, queried via
//! `GET /v1/mesh/status`. Generous timeouts keep it robust; the deterministic
//! membership/failure logic is covered by the channel-transport test.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use citadel_agent::http::{router, HttpTransport};
use citadel_agent::{build_node, peer_id, peer_public_key, spawn_node, MemberRow};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

const EPOCH: u64 = 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_agents_converge_over_http() {
    let mesh_id = MeshId::new("http-test-mesh");
    let seeds = [1u8, 2, 3];

    // Bind ephemeral ports first so every agent can be addressed by URL.
    let mut listeners = Vec::new();
    let mut urls: HashMap<u8, String> = HashMap::new();
    for &s in &seeds {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        urls.insert(s, format!("http://{addr}"));
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
        suspicion_timeout: 3,
        ..NodeConfig::default()
    };

    let mut status_urls = Vec::new();
    for (s, listener) in listeners {
        let url_map: HashMap<NodeId, String> = seeds
            .iter()
            .filter(|p| **p != s)
            .map(|p| (peer_id(&mesh_id, EPOCH, *p), urls[p].clone()))
            .collect();
        let (node, _id) = build_node(&mesh_id, s, "worker", cfg.clone(), &roster);
        let transport = Arc::new(HttpTransport::new(url_map));
        let handle = spawn_node(node, transport, Duration::from_millis(40));
        let app = router(handle);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        status_urls.push(format!("{}/v1/mesh/status", urls[&s]));
    }

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut converged = false;
    while Instant::now() < deadline {
        let mut all = true;
        for url in &status_urls {
            let rows: Vec<MemberRow> = match client.get(url).send().await {
                Ok(r) => r.json().await.unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            if rows.len() != 3 || rows.iter().filter(|r| r.liveness == "alive").count() != 3 {
                all = false;
                break;
            }
        }
        if all {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        converged,
        "three agents should converge on a live membership over HTTP"
    );
}
