//! Late-join convergence: a node that joins *after* the mesh has converged (and
//! after others' verdicts were already gossiped) still reaches mutual trust.
//!
//! Finding (from the live-mesh deployment exercise): the partial convergence seen
//! when agents were started *sequentially* is not a missing-anti-entropy gap in
//! the mesh — periodic re-attestation (`run_witness_duties` every
//! `attestation_interval`) continually re-gossips fresh verdicts, so a late
//! joiner receives them on the next round and converges. This guards that.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

#[test]
fn a_late_joining_node_converges_with_the_mesh() {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    // A 6-node mesh (witness_count 3 → a late joiner does NOT witness everyone)
    // converges first.
    let initial: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(28);
    assert_eq!(
        mesh.trust_of(initial[1], initial[0]),
        Some(TrustState::Trusted)
    );

    // A 7th node joins late — after the originals' verdicts were already gossiped.
    let late = mesh.add_node(7, "worker", cfg.clone());
    mesh.wire_full_membership();
    mesh.run(40);

    // It converges on the originals (including subjects it doesn't itself witness,
    // via re-gossiped verdicts) and they converge on it.
    for &n in &initial {
        assert_eq!(
            mesh.trust_of(late, n),
            Some(TrustState::Trusted),
            "late node trusts {n:?}"
        );
        assert_eq!(
            mesh.trust_of(n, late),
            Some(TrustState::Trusted),
            "{n:?} trusts the late node"
        );
    }
}
