//! Phase 3 acceptance (design §19, Phase 3 — Witness Sets):
//!
//! * each node has assigned witnesses (deterministic, every observer agrees);
//! * witnesses periodically challenge their subjects, so trust converges by
//!   quorum with no manual challenge;
//! * a tampered node is driven `Suspicious` by its witness quorum across the
//!   whole cluster — not by any single observer;
//! * the dashboard shows the witness-agreement ratio.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn mesh_of(n: u8, witness_count: usize) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

#[test]
fn each_subject_has_assigned_witnesses_all_observers_agree() {
    let (mesh, ids) = mesh_of(6, 3);
    for &subject in &ids {
        let canonical = mesh.assigned_witnesses(ids[0], subject);
        assert_eq!(canonical.len(), 3, "k=3 witnesses per subject");
        assert!(
            !canonical.contains(&subject),
            "subject is not its own witness"
        );
        // Assignment is deterministic, so every node computes the same set.
        for &observer in &ids {
            assert_eq!(
                mesh.assigned_witnesses(observer, subject),
                canonical,
                "all observers agree on the witness set"
            );
        }
    }
}

#[test]
fn witnesses_drive_trust_to_trusted_without_manual_challenge() {
    let (mut mesh, ids) = mesh_of(6, 3);
    // No manual challenge_peer calls — only automatic witness duties.
    mesh.run(12);

    for &observer in &ids {
        for &subject in &ids {
            if observer == subject {
                continue;
            }
            assert_eq!(
                mesh.trust_of(observer, subject),
                Some(TrustState::Trusted),
                "{observer} should see healthy {subject} trusted via witness quorum"
            );
        }
    }
}

#[test]
fn tampered_node_is_quarantined_by_witness_quorum() {
    let (mut mesh, ids) = mesh_of(6, 3);
    mesh.run(12);
    let victim = ids[4];

    // The victim's measured state diverges (stand-in for compromise).
    mesh.node(victim)
        .attestor()
        .backend()
        .pcr_extend("sha256", 0, &[0xAA; 32])
        .unwrap();
    mesh.run(12);

    // Every other node — not just one observer — sees the victim suspicious.
    for &observer in &ids {
        if observer == victim {
            continue;
        }
        assert_eq!(
            mesh.trust_of(observer, victim),
            Some(TrustState::Suspicious),
            "{observer} should quarantine the tampered {victim}"
        );
        // Healthy peers remain trusted in the same view.
        let healthy = ids[0];
        if observer != healthy {
            assert_eq!(mesh.trust_of(observer, healthy), Some(TrustState::Trusted));
        }
    }
}

#[test]
fn dashboard_shows_witness_agreement_ratio() {
    let (mut mesh, ids) = mesh_of(6, 3);
    mesh.run(12);

    // Healthy node: its assigned witnesses all report pass.
    let healthy = ids[1];
    let s = mesh.witness_summary(ids[0], healthy);
    assert_eq!(s.assigned, 3);
    assert!(s.reported >= s.quorum, "a quorum has reported: {s:?}");
    assert_eq!(s.fail, 0, "healthy node has no failing witnesses: {s:?}");
    assert!(s.pass >= s.quorum, "healthy node passes by quorum: {s:?}");

    // Tampered node: witnesses agree on failure.
    let victim = ids[4];
    mesh.node(victim)
        .attestor()
        .backend()
        .pcr_extend("sha256", 0, &[0xBB; 32])
        .unwrap();
    mesh.run(12);
    let s = mesh.witness_summary(ids[0], victim);
    assert!(
        s.fail >= s.quorum,
        "witnesses agree the victim failed: {s:?}"
    );
}
