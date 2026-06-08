//! M1 — a verifier's AttestationResult is signed and verifiable detached from
//! its gossip envelope (the basis for control-plane agreement).
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::types::{AttestationResult, ReasonCode, Verdict};
use citadel_mesh::NodeId;

fn result(verifier: NodeId) -> AttestationResult {
    AttestationResult {
        subject: NodeId([1u8; 32]),
        verifier,
        result: Verdict::Fail,
        reason_codes: vec![ReasonCode::PcrMismatch],
        policy_revision: 7,
        confidence: 0.9,
        timestamp_tick: 42,
        signature: citadel_mesh::crypto::Signature::zero(),
    }
}

#[test]
fn signed_verdict_verifies_and_tampering_is_rejected() {
    let verifier_kp = MeshKeypair::from_seed([9u8; 32]);
    let verifier = NodeId([2u8; 32]);
    let signed = result(verifier).signed(&verifier_kp);

    // Verifies against the verifier's key.
    assert!(signed.verify_signature(&verifier_kp.public()));
    // Not against a different key (impersonation).
    let other = MeshKeypair::from_seed([10u8; 32]);
    assert!(!signed.verify_signature(&other.public()));
    // Unsigned (zero) doesn't verify.
    assert!(!result(verifier).verify_signature(&verifier_kp.public()));

    // Tampering any signed field invalidates it.
    let mut flipped = signed.clone();
    flipped.result = Verdict::Pass;
    assert!(
        !flipped.verify_signature(&verifier_kp.public()),
        "flipped verdict must fail"
    );
    let mut relabelled = signed.clone();
    relabelled.subject = NodeId([0xFF; 32]);
    assert!(
        !relabelled.verify_signature(&verifier_kp.public()),
        "swapped subject must fail"
    );
}
