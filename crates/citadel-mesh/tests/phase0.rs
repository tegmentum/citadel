//! Phase 0 acceptance (design §19, Phase 0):
//!
//! * 3 agents form a mesh and gossip liveness.
//! * A failed node is detected: `Alive → Suspect → Faulty`.
//! * A restarted node refutes the suspicion with a higher incarnation.
//! * Mock attestation challenge/response drives trust state.
//! * A "dashboard" fleet view reflects node states.
//!
//! All of it runs in-process and deterministically (no sockets/threads).

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::{LivenessState, TrustState};

fn three_node_mesh() -> (Mesh, [citadel_mesh::NodeId; 3]) {
    let mut mesh = Mesh::new("prod-east-1");
    let a = mesh.add_node(1, "worker", NodeConfig::default());
    let b = mesh.add_node(2, "worker", NodeConfig::default());
    let c = mesh.add_node(3, "worker", NodeConfig::default());
    mesh.wire_full_membership();
    (mesh, [a, b, c])
}

#[test]
fn three_nodes_form_a_mesh_and_gossip_liveness() {
    let (mut mesh, [a, b, c]) = three_node_mesh();
    mesh.run(10);

    for &observer in &[a, b, c] {
        for &subject in &[a, b, c] {
            assert_eq!(
                mesh.liveness_of(observer, subject),
                Some(LivenessState::Alive),
                "{} should see {} alive",
                observer,
                subject
            );
        }
        let view = mesh.fleet_view(observer);
        assert_eq!(view.total, 3);
        assert_eq!(view.alive, 3, "all three alive in {}'s view", observer);
        assert_eq!(view.faulty, 0);
    }
}

#[test]
fn a_failed_node_is_detected_suspect_then_faulty() {
    let (mut mesh, [a, b, c]) = three_node_mesh();
    mesh.run(5);

    // C crashes / partitions away.
    mesh.kill(c);
    mesh.run(20);

    // Both surviving peers independently converge on C being faulty.
    assert_eq!(mesh.liveness_of(a, c), Some(LivenessState::Faulty), "A detects C faulty");
    assert_eq!(mesh.liveness_of(b, c), Some(LivenessState::Faulty), "B detects C faulty");

    // A and B still see each other alive — a partition is not a compromise.
    assert_eq!(mesh.liveness_of(a, b), Some(LivenessState::Alive));
    assert_eq!(mesh.liveness_of(b, a), Some(LivenessState::Alive));

    let view = mesh.fleet_view(a);
    assert_eq!(view.faulty, 1);
    assert_eq!(view.alive, 2);
}

#[test]
fn a_restarted_node_refutes_suspicion_with_higher_incarnation() {
    let (mut mesh, [a, b, c]) = three_node_mesh();
    mesh.run(5);
    mesh.kill(c);
    mesh.run(20);
    assert_eq!(mesh.liveness_of(a, c), Some(LivenessState::Faulty));

    // C comes back and must clear the stale suspicion.
    mesh.revive(c);
    mesh.run(20);

    assert_eq!(mesh.liveness_of(a, c), Some(LivenessState::Alive), "A re-admits C as alive");
    assert_eq!(mesh.liveness_of(b, c), Some(LivenessState::Alive), "B re-admits C as alive");
    assert!(
        mesh.node(c).membership().my_incarnation() >= 1,
        "C bumped its incarnation to refute"
    );
}

#[test]
fn mock_attestation_challenge_response_drives_trust() {
    // Isolate the *manual* (single-challenger) attestation path: disable
    // automatic witnessing so trust changes only when A challenges B.
    // (Quorum-driven witness attestation is covered by the Phase 3 tests.)
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = || NodeConfig {
        witness_count: 0,
        ..NodeConfig::default()
    };
    let a = mesh.add_node(1, "worker", cfg());
    let b = mesh.add_node(2, "worker", cfg());
    let _c = mesh.add_node(3, "worker", cfg());
    mesh.wire_full_membership();
    mesh.run(5);

    // Before any attestation, A has not classified B's trust.
    assert_eq!(mesh.trust_of(a, b), Some(TrustState::Unknown));

    // A challenges B; B answers with a healthy quote → Trusted.
    mesh.node_mut(a).challenge_peer(b);
    mesh.run(5);
    assert_eq!(mesh.trust_of(a, b), Some(TrustState::Trusted), "healthy B is trusted");

    // B's measured state diverges (a stand-in for compromise): its next
    // quote no longer matches the verifier's reference PCRs.
    mesh.node(b)
        .attestor()
        .backend()
        .pcr_extend("sha256", 0, &[0xAA; 32])
        .unwrap();

    mesh.node_mut(a).challenge_peer(b);
    mesh.run(5);
    assert_eq!(
        mesh.trust_of(a, b),
        Some(TrustState::Suspicious),
        "a PCR mismatch makes B suspicious"
    );
}

#[test]
fn dashboard_fleet_view_reflects_states() {
    let (mut mesh, [a, b, c]) = three_node_mesh();
    mesh.run(5);
    mesh.node_mut(a).challenge_peer(b);
    mesh.run(5);

    // A's "dashboard": everyone alive, self + attested B trusted.
    let view = mesh.fleet_view(a);
    assert_eq!(view.total, 3);
    assert_eq!(view.alive, 3);
    assert!(view.trusted >= 2, "self and attested B are trusted: {view:?}");

    // The per-node rows enumerate the whole mesh.
    let rows = mesh.rows_as_seen_by(a);
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.liveness == LivenessState::Alive));
    let _ = c; // present in the roster, unattested
}
