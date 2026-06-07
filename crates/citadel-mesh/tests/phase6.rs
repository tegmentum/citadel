//! Phase 6 acceptance (design §19, Phase 6 — Quarantine):
//!
//! * a suspicious node can be moved to `RestrictMeshVoting` by quorum (and
//!   then loses its vote);
//! * stronger isolation requires a higher quorum *and* an operator;
//! * rejoin requires fresh attestation and returns the node to probation.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::quarantine::QuarantineScope;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn founded_mesh(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 5,
        attestation_interval: 3,
        probation_period: 6,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(12);
    (mesh, ids)
}

/// Tamper a node's measured state and let the mesh classify it suspicious.
fn make_suspicious(mesh: &mut Mesh, victim: NodeId) {
    mesh.node(victim)
        .attestor()
        .backend()
        .pcr_extend("sha256", 0, &[0xAA; 32])
        .unwrap();
    mesh.run(15);
}

#[test]
fn suspicious_node_is_restricted_from_voting_by_quorum() {
    let (mut mesh, ids) = founded_mesh(8);
    let victim = ids[6];
    make_suspicious(&mut mesh, victim);
    assert_eq!(mesh.trust_of(ids[0], victim), Some(TrustState::Suspicious));

    let decision =
        mesh.propose_quarantine(ids[0], victim, QuarantineScope::RestrictMeshVoting, false);
    assert!(
        decision.enacted,
        "quorum should restrict a suspicious node: {decision:?}"
    );
    assert_eq!(
        mesh.quarantine_of(victim),
        Some(QuarantineScope::RestrictMeshVoting)
    );
    assert!(
        !mesh.is_eligible_voter(victim),
        "a restricted node cannot vote"
    );
}

#[test]
fn stronger_isolation_requires_higher_quorum_and_an_operator() {
    let (mut mesh, ids) = founded_mesh(8);
    let victim = ids[6];
    make_suspicious(&mut mesh, victim);

    // Witness votes alone cannot fully isolate — it needs an operator.
    let without_operator =
        mesh.propose_quarantine(ids[0], victim, QuarantineScope::FullIsolation, false);
    assert!(!without_operator.enacted);
    assert!(without_operator.operator_required);
    assert_ne!(
        mesh.quarantine_of(victim),
        Some(QuarantineScope::FullIsolation)
    );

    // With the operator's sign-off, the same quorum enacts it.
    let with_operator =
        mesh.propose_quarantine(ids[0], victim, QuarantineScope::FullIsolation, true);
    assert!(
        with_operator.enacted,
        "operator + quorum isolates: {with_operator:?}"
    );
    assert_eq!(
        mesh.quarantine_of(victim),
        Some(QuarantineScope::FullIsolation)
    );
    assert_eq!(mesh.trust_of(ids[0], victim), Some(TrustState::Isolated));
}

#[test]
fn isolated_node_rejoins_to_probation_after_fresh_attestation() {
    let (mut mesh, ids) = founded_mesh(8);
    let victim = ids[6];
    make_suspicious(&mut mesh, victim);

    // Quorum network-isolates the node (no operator needed at this scope).
    let decision = mesh.propose_quarantine(ids[0], victim, QuarantineScope::NetworkIsolate, false);
    assert!(decision.enacted);
    assert_eq!(mesh.trust_of(ids[0], victim), Some(TrustState::Isolated));

    // A stale, still-divergent node cannot rejoin: re-attestation fails.
    assert!(!mesh.rejoin(victim), "an unremediated node cannot rejoin");
    assert_eq!(mesh.trust_of(ids[0], victim), Some(TrustState::Isolated));

    // After remediation (clean reimage), it re-attests and a quorum votes it
    // back — to probation, not straight to trusted.
    mesh.remediate(victim);
    assert!(
        mesh.rejoin(victim),
        "a remediated node rejoins on fresh attestation"
    );
    assert_eq!(
        mesh.trust_of(ids[0], victim),
        Some(TrustState::Probationary),
        "rejoin returns the node to probation, not trusted"
    );

    // It then earns trust again through the normal probation window.
    mesh.run(20);
    assert_eq!(mesh.trust_of(ids[0], victim), Some(TrustState::Trusted));
}
