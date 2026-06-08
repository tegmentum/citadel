//! Node validation (B1/C1, Task 2): real agent processes over the HTTP transport
//! ship and appraise the measured state the agent reads from securityfs.
//!
//! The "bad" agent stages real kernel IMA lines (from the captured corpus,
//! `/sys/.../ascii_runtime_measurements`) the same way `citadel-agent` does at
//! startup; the fleet denylists a binary that is actually in that list. Over
//! real sockets the witness challenges the bad node, receives its shipped IMA
//! log, appraises it, and distrusts it — end to end, no in-process harness.
//! (A compact slice keeps the gossiped evidence small so the test is fast.)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use citadel_agent::http::{router, HttpTransport};
use citadel_agent::{
    build_node, peer_id, peer_public_key, spawn_node, stage_node_logs, AgentHandle,
};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::runtime::RuntimePolicy;
use citadel_mesh::NodeId;

const EPOCH: u64 = 1;

fn captured_ima_list() -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tpm-core/tests/fixtures/ima/ubuntu-24.04-tcb-amd64.ascii");
    tpm_core::sys::ima_runtime_list_at(&path)
        .expect("read the captured IMA corpus")
        .expect("the IMA fixture is present")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_shipping_a_denylisted_ima_file_is_distrusted_over_http() {
    // Read the real IMA list (proving the reader handles the real bytes) and use
    // a compact slice of it — the first measured files — as the shipped evidence,
    // so the attestation payload stays small. These are still real kernel lines.
    let full = captured_ima_list();
    let ima_text: String = full.lines().take(12).collect::<Vec<_>>().join("\n") + "\n";
    let (parsed, skipped) = tpm_core::ima::ImaLog::parse_ascii(&ima_text);
    assert_eq!(skipped, 0, "the captured list parses cleanly");
    let target = parsed
        .entries
        .iter()
        .find(|e| e.path != "boot_aggregate")
        .expect("the list measures at least one real file");
    let deny_algo = target.file_algo.clone();
    let deny_hash = target.file_hash.clone();

    let mesh_id = MeshId::new("node-validation");
    let seeds = [1u8, 2, 3, 4];
    let bad_seed = 4u8;

    // Bind ephemeral ports so the agents can address each other over HTTP.
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
        witness_count: 3,
        attestation_interval: 2,
        probe_interval: 1,
        ..NodeConfig::default()
    };

    let mut handles: HashMap<u8, AgentHandle> = HashMap::new();
    let mut servers = Vec::new();
    for (s, listener) in listeners {
        let url_map: HashMap<NodeId, String> = seeds
            .iter()
            .filter(|p| **p != s)
            .map(|p| (peer_id(&mesh_id, EPOCH, *p), urls[p].clone()))
            .collect();
        let (mut node, _id) = build_node(&mesh_id, s, "worker", cfg.clone(), &roster);
        // Every node, as a verifier, denylists the bad binary (fleet policy).
        node.set_runtime_policy(RuntimePolicy::new().deny(deny_algo.clone(), deny_hash.clone()));
        // Only the bad node stages the real IMA list (which contains the
        // denylisted binary) — exactly the startup path the agent runs from /sys.
        if s == bad_seed {
            let (_fw, ima_entries) = stage_node_logs(&mut node, None, Some(&ima_text));
            assert!(
                ima_entries > 1,
                "the real list ingested ({ima_entries} entries)"
            );
        }
        let handle = spawn_node(
            node,
            Arc::new(HttpTransport::new(url_map)),
            Duration::from_millis(30),
        );
        let app = router(handle.clone());
        servers.push(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        handles.insert(s, handle);
    }

    let bad_id = peer_id(&mesh_id, EPOCH, bad_seed);
    let clean_id = peer_id(&mesh_id, EPOCH, 2);
    let witness = &handles[&1];

    // Membership forms, the witness challenges the bad node, receives its shipped
    // IMA log, appraises it, and distrusts it.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut bad_trust = None;
    while Instant::now() < deadline {
        bad_trust = witness.trust_of(bad_id).await;
        if bad_trust.as_deref() == Some("suspicious") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        bad_trust.as_deref(),
        Some("suspicious"),
        "the witness distrusts the node whose shipped IMA list contains a denylisted file"
    );

    // The distrust is targeted: a node that shipped no denylisted file is not
    // flagged suspicious.
    assert_ne!(
        witness.trust_of(clean_id).await.as_deref(),
        Some("suspicious"),
        "a node with a clean (or no) runtime list is not distrusted"
    );

    // Stop the agents and HTTP servers so the runtime tears down promptly.
    for h in handles.values() {
        h.shutdown();
    }
    for s in servers {
        s.abort();
    }
}
