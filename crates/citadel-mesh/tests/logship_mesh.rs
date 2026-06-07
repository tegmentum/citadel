//! Log-shipping wired into the live mesh: a node's measurement log replicates
//! to every peer by gossiping LtHash digests and pulling the divergent
//! windows, and a node that forks its own (sealed) history is detected as
//! equivocating and distrusted.

use citadel_mesh::evidence::payload_hash;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn log_cfg() -> NodeConfig {
    NodeConfig {
        // Focus on log-shipping: no attestation traffic, brisk advertising.
        witness_count: 0,
        log_window_size: 8,
        log_advertise_interval: 2,
        ..NodeConfig::default()
    }
}

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", log_cfg()))
        .collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

#[test]
fn a_nodes_log_replicates_to_every_peer() {
    let (mut mesh, ids) = mesh_of(4);
    let origin = ids[0];

    // The origin records a run of measurement events (spanning 3 windows).
    for i in 0..20u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("event-{i}").as_bytes()));
    }
    mesh.run(25);

    let origin_root = mesh.node(origin).own_log_root();
    for &peer in &ids[1..] {
        assert_eq!(
            mesh.node(peer).replica_root(origin),
            Some(origin_root.clone()),
            "{peer} should hold a faithful replica of {origin}'s log"
        );
    }
}

#[test]
fn incremental_events_keep_replicas_in_sync() {
    let (mut mesh, ids) = mesh_of(3);
    let origin = ids[0];

    for i in 0..10u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("a-{i}").as_bytes()));
    }
    mesh.run(15);
    // More events arrive later — replicas catch up.
    for i in 10..24u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("a-{i}").as_bytes()));
    }
    mesh.run(20);

    let root = mesh.node(origin).own_log_root();
    assert_eq!(mesh.node(ids[1]).replica_root(origin), Some(root.clone()));
    assert_eq!(mesh.node(ids[2]).replica_root(origin), Some(root));
}

#[test]
fn incremental_divergence_transfers_only_the_diff_not_the_whole_window() {
    // A large window so a few new records are a small fraction of it.
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 0,
        log_window_size: 64,
        log_advertise_interval: 2,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=3)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    let origin = ids[0];

    // First sync: 40 events in window 0; replicas catch up.
    for i in 0..40u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("e-{i}").as_bytes()));
    }
    mesh.run(20);
    let baseline_served = mesh.node(origin).log_records_served();

    // Ten more events land in the *same* window.
    for i in 40..50u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("e-{i}").as_bytes()));
    }
    mesh.run(20);

    // The replicas converge again...
    let root = mesh.node(origin).own_log_root();
    for &peer in &ids[1..] {
        assert_eq!(mesh.node(peer).replica_root(origin), Some(root.clone()));
    }
    // ...having pulled only the divergent tail (≈10 records × 2 replicas),
    // not the whole 50-record window (which would be ≈100).
    let delta = mesh.node(origin).log_records_served() - baseline_served;
    assert!(
        delta < 40,
        "binary search should transfer only the diff, served delta = {delta}"
    );
}

#[test]
fn a_node_forking_its_own_history_is_detected_and_distrusted() {
    let (mut mesh, ids) = mesh_of(4);
    let forker = ids[2];

    // Build and ship a log; window 0 (seq 0..8) seals once we pass it.
    for i in 0..12u64 {
        mesh.node_mut(forker)
            .append_event(payload_hash(format!("orig-{i}").as_bytes()));
    }
    mesh.run(15);
    // Peers have recorded the sealed window-0 root and trust nothing-bad yet.
    assert_ne!(mesh.trust_of(ids[0], forker), Some(TrustState::Suspicious));

    // The node rewrites a sealed event — forking its own history.
    mesh.node_mut(forker)
        .rewrite_event(3, payload_hash(b"forged"));
    mesh.run(15);

    // Every peer sees the conflicting sealed-window root and distrusts it.
    for &peer in &ids {
        if peer != forker {
            assert_eq!(
                mesh.trust_of(peer, forker),
                Some(TrustState::Suspicious),
                "{peer} should distrust the equivocating {forker}"
            );
        }
    }
}
