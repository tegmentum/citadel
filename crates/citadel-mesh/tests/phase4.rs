//! Phase 4 acceptance (design §19, Phase 4 — Distributed Evidence):
//!
//! * evidence survives the loss of `total - threshold` fragment holders;
//! * a reconstruction proof is emitted;
//! * (local evidence-chain rewrite detection is unit-tested in
//!   `evidence.rs`, where a test can model an attacker mutating the
//!   append-only chain it otherwise cannot reach).
//!
//! Here we drive the *distributed* path through the public API: encode a
//! payload, scatter the fragments to HRW-assigned holders across a roster,
//! lose a batch of holders, and rebuild from what remains.

use std::collections::HashMap;

use citadel_mesh::erasure::{self, ErasureScheme, EvidenceFragment};
use citadel_mesh::evidence::{self, audit_reconstruction, payload_hash};
use citadel_mesh::NodeId;

fn roster(n: u8) -> Vec<NodeId> {
    (1..=n).map(|i| NodeId([i; 32])).collect()
}

/// Scatter one fragment per holder across the roster (N fragments → N
/// holders), returning a holder→fragment map.
fn scatter(
    record_id: [u8; 32],
    fragments: &[EvidenceFragment],
    roster: &[NodeId],
) -> HashMap<NodeId, EvidenceFragment> {
    let holders = evidence::assign_holders(record_id, roster, fragments.len());
    assert_eq!(holders.len(), fragments.len(), "a distinct holder per fragment");
    holders.into_iter().zip(fragments.iter().cloned()).collect()
}

#[test]
fn evidence_survives_loss_of_total_minus_threshold_holders() {
    let roster = roster(20);
    let payload = b"node-1842 attestation evidence @ 08:42:17Z, kept against deletion".to_vec();
    let rid = payload_hash(&payload);

    // N = 20 fragments, reconstruct from any K = 7 (design example).
    let scheme = ErasureScheme::new(7, 13).unwrap();
    let fragments = scheme.encode(rid, &payload).unwrap();
    let mut vault = scatter(rid, &fragments, &roster);
    assert_eq!(vault.len(), 20);

    // Lose 13 holders (deleted / isolated / ransomwared) — keep any 7.
    let casualties: Vec<NodeId> = vault.keys().copied().take(13).collect();
    for c in &casualties {
        vault.remove(c);
    }
    assert_eq!(vault.len(), 7);

    // The evidence still reconstructs from the surviving holders.
    let surviving: Vec<EvidenceFragment> = vault.values().cloned().collect();
    assert_eq!(erasure::reconstruct(&surviving).unwrap(), payload);

    // Durability is exactly at the threshold (7/7).
    assert_eq!(erasure::durability(surviving.len(), 7), 1.0);

    // Losing one more drops below the threshold: no longer reconstructable.
    let below: Vec<EvidenceFragment> = surviving.iter().skip(1).cloned().collect();
    assert!(erasure::durability(below.len(), 7) < 1.0);
    assert!(erasure::reconstruct(&below).is_err());
}

#[test]
fn reconstruction_audit_emits_a_proof() {
    let roster = roster(20);
    let payload = b"quarantine decision record for node-1842".to_vec();
    let rid = payload_hash(&payload);
    let scheme = ErasureScheme::new(7, 13).unwrap();
    let fragments = scheme.encode(rid, &payload).unwrap();
    let mut vault = scatter(rid, &fragments, &roster);

    // Lose 12 holders; 8 remain (above the threshold of 7).
    for c in vault.keys().copied().take(12).collect::<Vec<_>>() {
        vault.remove(&c);
    }
    let available: Vec<EvidenceFragment> = vault.values().cloned().collect();

    let proof = audit_reconstruction(rid, rid, &available, NodeId([99; 32]), 4242);
    assert!(proof.success, "reconstruction proof should succeed");
    assert_eq!(proof.reconstructed_payload_hash, rid);
    assert_eq!(proof.record_id, rid);
    assert!(proof.received >= 7);
}
