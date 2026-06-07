//! Witness assignment (design §10).
//!
//! Every node is watched by a **witness set** — a small group of peers that
//! periodically attest it and publish signed results. The mesh decides a
//! node's trust from the *agreement* of its witnesses, not from any single
//! observer, so a compromised node must also subvert a quorum of its
//! witnesses to hide.
//!
//! Assignment here is **deterministic from the mesh epoch** via rendezvous
//! (highest-random-weight) hashing: every node, given the same roster and
//! epoch, computes the same witness set for a subject with no coordinator
//! (design open question §21.8 — we take the decentralized option). The
//! subject is never its own witness. Rotation is free: bump the epoch and
//! every set reshuffles. Failure-domain diversity (§10.4) is a later
//! refinement layered on top of this base assignment.

use crate::id::{Epoch, NodeId};

/// A subject's assigned witnesses and the quorum needed to decide its trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSet {
    pub subject: NodeId,
    pub witnesses: Vec<NodeId>,
    /// Minimum agreeing witness reports required for a confident decision.
    pub quorum_threshold: usize,
    pub assignment_epoch: Epoch,
}

/// Rendezvous (HRW) weight of `candidate` for `subject` at `epoch`: a node
/// scores high (and is chosen) when this hash is large. Mixing the subject
/// and epoch in makes the set subject-specific and rotates it per epoch.
fn weight(candidate: &NodeId, subject: &NodeId, epoch: Epoch) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"citadel-witness-hrw\x00");
    h.update(&subject.0);
    h.update(&epoch.0.to_be_bytes());
    h.update(&candidate.0);
    *h.finalize().as_bytes()
}

/// Choose the witness set for `subject` from `roster` at `epoch`: the up-to-`k`
/// highest-weight peers, excluding the subject itself. `roster` may include
/// the subject (it is filtered out). Ties break by `NodeId` for determinism.
pub fn assign(subject: NodeId, roster: &[NodeId], epoch: Epoch, k: usize) -> WitnessSet {
    let mut scored: Vec<(([u8; 32], NodeId), NodeId)> = roster
        .iter()
        .filter(|n| **n != subject)
        .map(|n| ((weight(n, &subject, epoch), *n), *n))
        .collect();
    // Sort by (weight desc, node_id desc) — deterministic total order.
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let witnesses: Vec<NodeId> = scored.into_iter().take(k).map(|(_, n)| n).collect();
    // Strict majority of the *assigned* witnesses (at least 1).
    let quorum_threshold = witnesses.len() / 2 + 1;
    WitnessSet {
        subject,
        witnesses,
        quorum_threshold,
        assignment_epoch: epoch,
    }
}

/// Is `candidate` a witness for `subject` under this roster/epoch/`k`?
pub fn is_witness(
    candidate: NodeId,
    subject: NodeId,
    roster: &[NodeId],
    epoch: Epoch,
    k: usize,
) -> bool {
    assign(subject, roster, epoch, k)
        .witnesses
        .contains(&candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster(n: u8) -> Vec<NodeId> {
        (1..=n).map(|i| NodeId([i; 32])).collect()
    }

    #[test]
    fn assignment_is_deterministic_and_sized() {
        let r = roster(10);
        let a = assign(NodeId([3; 32]), &r, Epoch(1), 4);
        let b = assign(NodeId([3; 32]), &r, Epoch(1), 4);
        assert_eq!(a, b, "same roster/epoch → same set");
        assert_eq!(a.witnesses.len(), 4);
        assert_eq!(a.quorum_threshold, 3);
    }

    #[test]
    fn subject_is_never_its_own_witness() {
        let r = roster(10);
        for i in 1..=10u8 {
            let s = NodeId([i; 32]);
            let ws = assign(s, &r, Epoch(7), 5);
            assert!(!ws.witnesses.contains(&s), "subject excluded");
        }
    }

    #[test]
    fn epoch_rotates_the_set() {
        let r = roster(20);
        let s = NodeId([5; 32]);
        let e1 = assign(s, &r, Epoch(1), 5).witnesses;
        let e2 = assign(s, &r, Epoch(2), 5).witnesses;
        assert_ne!(e1, e2, "a new epoch reshuffles witnesses");
    }

    #[test]
    fn k_larger_than_roster_is_clamped() {
        let r = roster(3);
        let ws = assign(NodeId([1; 32]), &r, Epoch(1), 10);
        assert_eq!(ws.witnesses.len(), 2, "only the other two can witness");
    }

    #[test]
    fn assignment_is_balanced_across_the_roster() {
        // Every node should witness a roughly even share — no hot spots.
        let r = roster(30);
        let k = 5;
        let mut load = std::collections::HashMap::new();
        for &s in &r {
            for w in assign(s, &r, Epoch(1), k).witnesses {
                *load.entry(w).or_insert(0usize) += 1;
            }
        }
        let total: usize = load.values().sum();
        assert_eq!(total, 30 * k);
        let max = *load.values().max().unwrap();
        // HRW spreads work across the roster: almost every node witnesses
        // someone, and no node carries a wildly disproportionate share
        // (avg is k=5; allow up to ~2.5x before calling it a hot spot).
        assert!(
            load.len() >= 27,
            "most nodes should witness: {} of 30",
            load.len()
        );
        assert!(max <= 12, "no witness hot spot: max {max}");
    }

    #[test]
    fn is_witness_matches_assignment() {
        let r = roster(8);
        let s = NodeId([2; 32]);
        let ws = assign(s, &r, Epoch(3), 3);
        for &w in &ws.witnesses {
            assert!(is_witness(w, s, &r, Epoch(3), 3));
        }
    }
}
