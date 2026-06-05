//! Phase 5 acceptance (design §19, Phase 5 — Enrollment and Probation):
//!
//! * a new node joins only after quorum approval (and a tampered candidate
//!   is refused, never added);
//! * a new node cannot vote while on probation;
//! * a duplicate/cloned identity is flagged;
//! * a probationer is promoted to `Trusted` only after its probation window.

use citadel_mesh::enrollment::AdmissionReason;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

/// A founded mesh whose members have attested each other into mutual trust.
fn founded_mesh(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        probation_period: 6,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    mesh.run(12);
    (mesh, ids)
}

#[test]
fn healthy_node_joins_only_after_quorum_and_starts_probationary() {
    let (mut mesh, ids) = founded_mesh(6);
    let (outcome, candidate) = mesh.enroll(50, "worker");
    assert!(outcome.admitted, "quorum should admit a healthy candidate: {outcome:?}");
    assert!(outcome.approvals >= 2);
    // Admitted, but probationary — not immediately trusted (design §7.5).
    assert_eq!(mesh.trust_of(ids[0], candidate), Some(TrustState::Probationary));
}

#[test]
fn tampered_candidate_is_refused_and_not_added() {
    let (mut mesh, ids) = founded_mesh(6);
    let (outcome, candidate) = mesh.enroll_tampered(51, "worker");
    assert!(!outcome.admitted, "a divergent measured state must be refused");
    assert!(
        outcome.reject_reasons.contains(&AdmissionReason::AttestationFailed),
        "reasons: {:?}",
        outcome.reject_reasons
    );
    // Not admitted ⇒ no member knows it.
    assert_eq!(mesh.trust_of(ids[0], candidate), None);
}

#[test]
fn duplicate_identity_is_flagged() {
    let (mut mesh, _ids) = founded_mesh(6);
    let (first, _cand) = mesh.enroll(50, "worker");
    assert!(first.admitted);

    // Enrolling the same identity again (same key/node-id) is a duplicate.
    let (second, _) = mesh.enroll(50, "worker");
    assert!(!second.admitted);
    assert!(
        second.reject_reasons.contains(&AdmissionReason::DuplicateIdentity),
        "reasons: {:?}",
        second.reject_reasons
    );
}

#[test]
fn probationary_node_cannot_vote() {
    let (mut mesh, ids) = founded_mesh(6);
    let (outcome, candidate) = mesh.enroll(50, "worker");
    assert!(outcome.admitted);

    // A founder is an eligible voter; the freshly-admitted probationer is not.
    assert!(mesh.is_eligible_voter(ids[1]), "established founder may vote");
    assert!(
        !mesh.is_eligible_voter(candidate),
        "a probationary node may not vote on admissions"
    );
}

#[test]
fn probationer_is_promoted_after_its_window() {
    let (mut mesh, ids) = founded_mesh(6);
    let (outcome, candidate) = mesh.enroll(50, "worker");
    assert!(outcome.admitted);
    assert_eq!(mesh.trust_of(ids[0], candidate), Some(TrustState::Probationary));

    // Keep running: witnesses keep attesting the probationer, and once the
    // probation window elapses it is promoted to Trusted.
    mesh.run(20);
    assert_eq!(
        mesh.trust_of(ids[0], candidate),
        Some(TrustState::Trusted),
        "a clean probationer is promoted after its window"
    );
    // And now it may vote.
    assert!(mesh.is_eligible_voter(candidate));
}
