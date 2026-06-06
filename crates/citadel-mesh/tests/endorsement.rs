//! Item-2 acceptance: AK/EK endorsement closes the `AK_UNTRUSTED` gap. With
//! trust anchors configured, a node's quote is accepted only if its
//! attestation key carries a valid endorsement from a trusted endorser —
//! so a node with a self-asserted (unendorsed) AK cannot earn trust or join.

use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::enrollment::AdmissionReason;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn endorser() -> MeshKeypair {
    MeshKeypair::from_seed([200u8; 32])
}

fn cfg() -> NodeConfig {
    NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    }
}

#[test]
fn endorsed_mesh_converges_trusted() {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=6).map(|s| mesh.add_node(s, "worker", cfg())).collect();
    mesh.wire_full_membership();

    let e = endorser();
    mesh.set_anchors_all(TrustAnchors::with(e.public()));
    for &id in &ids {
        mesh.endorse(id, &e);
    }
    mesh.run(12);

    for &o in &ids {
        for &s in &ids {
            if o != s {
                assert_eq!(
                    mesh.trust_of(o, s),
                    Some(TrustState::Trusted),
                    "{o} should trust endorsed {s}"
                );
            }
        }
    }
}

#[test]
fn unendorsed_node_is_ak_untrusted_and_suspicious() {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=6).map(|s| mesh.add_node(s, "worker", cfg())).collect();
    mesh.wire_full_membership();

    let e = endorser();
    mesh.set_anchors_all(TrustAnchors::with(e.public()));
    // Endorse all but the last node — it has only a self-asserted AK.
    for &id in &ids[..5] {
        mesh.endorse(id, &e);
    }
    let rogue = ids[5];
    mesh.run(15);

    // Every endorsed node flags the unendorsed one as suspicious...
    for &o in &ids {
        if o != rogue {
            assert_eq!(
                mesh.trust_of(o, rogue),
                Some(TrustState::Suspicious),
                "{o} should distrust the unendorsed {rogue}"
            );
        }
    }
    // ...while the endorsed nodes still trust each other.
    assert_eq!(mesh.trust_of(ids[0], ids[1]), Some(TrustState::Trusted));
}

#[test]
fn enrollment_refuses_an_unendorsed_candidate() {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=6).map(|s| mesh.add_node(s, "worker", cfg())).collect();
    mesh.wire_full_membership();

    let e = endorser();
    mesh.set_anchors_all(TrustAnchors::with(e.public()));
    for &id in &ids {
        mesh.endorse(id, &e);
    }
    mesh.run(12);

    // A candidate with no endorsement is refused (its witnesses require one).
    let (outcome, candidate) = mesh.enroll(50, "worker");
    assert!(!outcome.admitted, "an unendorsed candidate must not be admitted");
    assert!(
        outcome.reject_reasons.contains(&AdmissionReason::AkUntrusted),
        "reasons: {:?}",
        outcome.reject_reasons
    );
    assert_eq!(mesh.trust_of(ids[0], candidate), None);
}
