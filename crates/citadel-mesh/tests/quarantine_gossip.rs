//! Quarantine is gossip-wired (design §13): a proposal + the subject's
//! witnesses' votes propagate, and every node converges on the same enactment —
//! with the most severe scopes gated on a relayed operator approval (CP5).

use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::quarantine::{OperatorQuarantineApproval, QuarantineScope};
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn suspicious_mesh() -> (Mesh, Vec<NodeId>, NodeId) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 4,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(12);
    // Tamper one node so its witnesses see it as Suspicious.
    let subject = workers[5];
    mesh.measured_state_change(subject, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(
        mesh.trust_of(workers[0], subject),
        Some(TrustState::Suspicious)
    );
    (mesh, workers, subject)
}

#[test]
fn a_light_scope_enacts_mesh_wide_from_witness_votes() {
    let (mut mesh, workers, subject) = suspicious_mesh();

    // A peer proposes restricting the subject's mesh voting; witnesses vote.
    let proposer = workers[0];
    mesh.node_mut(proposer).propose_and_broadcast_quarantine(
        subject,
        QuarantineScope::RestrictMeshVoting,
        30,
    );
    mesh.run(10);

    // Every node converges on the enacted scope from the gossiped votes.
    for &w in &workers {
        if w == subject {
            continue;
        }
        assert_eq!(
            mesh.node(w).quarantine_of(subject),
            Some(QuarantineScope::RestrictMeshVoting),
            "node {w} enacted the quorum-approved quarantine"
        );
    }
}

#[test]
fn full_isolation_waits_for_a_relayed_operator_approval() {
    let (mut mesh, workers, subject) = suspicious_mesh();
    let operator = MeshKeypair::from_seed([222; 32]);
    mesh.authorize_operator_key_all(operator.public());

    // Propose full isolation: witnesses approve, but the severe scope is gated
    // on an operator — so it does NOT enact yet.
    let proposer = workers[0];
    let pid = mesh.node_mut(proposer).propose_and_broadcast_quarantine(
        subject,
        QuarantineScope::FullIsolation,
        30,
    );
    mesh.run(10);
    for &w in &workers {
        assert_eq!(
            mesh.node(w).quarantine_of(subject),
            None,
            "witness votes alone must not fully isolate {subject}"
        );
    }

    // The control plane relays the operator's signed approval into the mesh.
    let approval = OperatorQuarantineApproval::sign(&operator, pid, 41);
    mesh.node_mut(workers[1])
        .relay_quarantine_approval(approval);
    mesh.run(10);

    for &w in &workers {
        if w == subject {
            continue;
        }
        assert_eq!(
            mesh.node(w).quarantine_of(subject),
            Some(QuarantineScope::FullIsolation),
            "with the operator approval, node {w} enacts full isolation"
        );
    }

    // The isolating quarantine freezes trust at `Isolated`: a fresh challenge
    // no longer downgrades it back to `Suspicious`.
    mesh.run(12);
    assert_eq!(
        mesh.trust_of(workers[0], subject),
        Some(TrustState::Isolated)
    );
}

#[test]
fn an_untrusted_operator_approval_is_ignored() {
    let (mut mesh, workers, subject) = suspicious_mesh();
    // This operator key is NOT authorized on the nodes.
    let impostor = MeshKeypair::from_seed([123; 32]);

    let pid = mesh.node_mut(workers[0]).propose_and_broadcast_quarantine(
        subject,
        QuarantineScope::FullIsolation,
        30,
    );
    mesh.run(10);
    let approval = OperatorQuarantineApproval::sign(&impostor, pid, 41);
    mesh.node_mut(workers[1])
        .relay_quarantine_approval(approval);
    mesh.run(10);

    for &w in &workers {
        assert_eq!(
            mesh.node(w).quarantine_of(subject),
            None,
            "an unauthorized operator approval cannot enact full isolation"
        );
    }
}
