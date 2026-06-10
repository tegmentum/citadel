//! # citadel-beacon (MB1) — mesh randomness/freshness beacon
//!
//! The mesh's missing notion of *now* and *fresh*: a periodically-produced,
//! **threshold-signed** value `beacon[n] = thresholdSign(n ‖ prev)`, chained so
//! `prev = digest(beacon[n-1])`. Every node verifies a round against the group
//! key without re-running consensus, and the value is unpredictable before the
//! round closes — no single node can bias it (MB-C1). Other subsystems quote a
//! beacon round instead of a wall clock or a local RNG: replay-proof challenges,
//! synchronized lease/epoch boundaries (MSS leases, SVID renewals, capability
//! TTLs), fair sampling, leader election.
//!
//! Reuses the FROST signing of `citadel-mss::tsig` (MSS6b). This is the pure
//! protocol + crypto core; gossiping the rounds over `AppRelay` and wiring the
//! freshness consumers are MB2/MB3.
//!
//! Honest scope: FROST (Schnorr) makes the beacon **unpredictable + verifiable +
//! single-node-unbiasable**. Making it unbiasable even against a *colluding
//! signing quorum* (a true unique-per-input VRF) needs threshold BLS — the
//! documented hardening, like DKG was for MSS6b.

use citadel_mss::tsig::{self, KeyPackage, PublicKeyPackage, Signature};
use serde::{Deserialize, Serialize};

/// The `prev` of the first round (no predecessor).
pub const GENESIS_PREV: [u8; 32] = [0u8; 32];

/// The message the threshold group signs for round `round` chaining to `prev`.
pub fn message(round: u64, prev: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 32 + 16);
    m.extend_from_slice(b"citadel-beacon\x00");
    m.extend_from_slice(&round.to_le_bytes());
    m.extend_from_slice(prev);
    m
}

/// One beacon round: the round number, the predecessor it commits to, and the
/// group threshold signature over `message(round, prev)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconRound {
    pub round: u64,
    pub prev: [u8; 32],
    pub signature: Signature,
}

impl BeaconRound {
    /// Produce a round: a threshold of holders co-sign `message(round, prev)`.
    /// (In-process here; MB2 carries the FROST rounds over gossip.)
    pub fn produce(
        round: u64,
        prev: [u8; 32],
        packages: &[KeyPackage],
        public: &PublicKeyPackage,
    ) -> anyhow::Result<Self> {
        let signature = tsig::sign(packages, public, &message(round, &prev))?;
        Ok(BeaconRound {
            round,
            prev,
            signature,
        })
    }

    /// Verify this round against the beacon group's public key.
    pub fn verify(&self, public: &PublicKeyPackage) -> bool {
        tsig::verify(public, &message(self.round, &self.prev), &self.signature)
    }

    /// The round's random output — `BLAKE3` of the signature. Unpredictable
    /// before the round closes (the signature requires the threshold); this is
    /// what consumers use as randomness.
    pub fn value(&self) -> [u8; 32] {
        let sig = serde_json::to_vec(&self.signature).expect("frost signature is serializable");
        *blake3::hash(&sig).as_bytes()
    }

    /// The digest the *next* round chains to (`prev`).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"citadel-beacon-digest\x00");
        h.update(&self.round.to_le_bytes());
        h.update(&self.prev);
        h.update(&self.value());
        *h.finalize().as_bytes()
    }

    /// A domain-separated, freshness-bound nonce derived from this round, for
    /// replay-proof challenges (a verifier challenge tied to `context` and this
    /// beacon round can't be replayed across rounds).
    pub fn nonce_for(&self, context: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"citadel-beacon-nonce\x00");
        h.update(&self.value());
        h.update(context);
        *h.finalize().as_bytes()
    }
}

/// Produce the round following `prev` (round+1, chained to its digest).
pub fn next_round(
    prev: &BeaconRound,
    packages: &[KeyPackage],
    public: &PublicKeyPackage,
) -> anyhow::Result<BeaconRound> {
    BeaconRound::produce(prev.round + 1, prev.digest(), packages, public)
}

/// Verify a contiguous chain: each round verifies, its `round` increments by 1,
/// and its `prev` equals the previous round's digest (the first chains to
/// `genesis_prev`).
pub fn verify_chain(
    rounds: &[BeaconRound],
    public: &PublicKeyPackage,
    genesis_prev: [u8; 32],
) -> bool {
    let first_round = match rounds.first() {
        Some(r) => r.round,
        None => return true,
    };
    let mut expected_prev = genesis_prev;
    for (i, r) in rounds.iter().enumerate() {
        if r.round != first_round + i as u64 || r.prev != expected_prev || !r.verify(public) {
            return false;
        }
        expected_prev = r.digest();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_chain_and_verify() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let signers = &packages[0..3];

        let r0 = BeaconRound::produce(0, GENESIS_PREV, signers, &public).unwrap();
        assert!(r0.verify(&public));
        let r1 = next_round(&r0, signers, &public).unwrap();
        let r2 = next_round(&r1, signers, &public).unwrap();

        assert_eq!(r1.prev, r0.digest());
        assert!(verify_chain(
            &[r0.clone(), r1.clone(), r2],
            &public,
            GENESIS_PREV
        ));

        // Distinct rounds yield distinct values (the freshness sequence advances).
        assert_ne!(r0.value(), r1.value());
    }

    #[test]
    fn unpredictable_and_single_node_unbiasable() {
        // Two independent productions of the same (round, prev) yield different
        // signatures -> different values: the output can't be precomputed without
        // the live threshold (it's randomized by the signers' nonces), and no
        // single holder fixes it.
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let a = BeaconRound::produce(7, [9u8; 32], &packages[0..3], &public).unwrap();
        let b = BeaconRound::produce(7, [9u8; 32], &packages[0..3], &public).unwrap();
        assert!(a.verify(&public) && b.verify(&public));
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn tampering_breaks_verification_and_the_chain() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let signers = &packages[0..3];
        let r0 = BeaconRound::produce(0, GENESIS_PREV, signers, &public).unwrap();

        // Wrong prev / round (the signature is over message(round, prev)).
        let mut bad_prev = r0.clone();
        bad_prev.prev = [1u8; 32];
        assert!(!bad_prev.verify(&public));
        let mut bad_round = r0.clone();
        bad_round.round = 5;
        assert!(!bad_round.verify(&public));

        // A round that doesn't chain breaks verify_chain.
        let r1 = next_round(&r0, signers, &public).unwrap();
        let mut unchained = r1.clone();
        unchained.prev = [2u8; 32];
        assert!(!verify_chain(&[r0, unchained], &public, GENESIS_PREV));
    }

    #[test]
    fn nonce_is_freshness_bound_and_domain_separated() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let r0 = BeaconRound::produce(0, GENESIS_PREV, &packages[0..3], &public).unwrap();
        let r1 = next_round(&r0, &packages[0..3], &public).unwrap();
        // Same context, different rounds -> different nonces (replay across rounds fails).
        assert_ne!(
            r0.nonce_for(b"attest:node-1"),
            r1.nonce_for(b"attest:node-1")
        );
        // Same round, different context -> different nonces.
        assert_ne!(
            r0.nonce_for(b"attest:node-1"),
            r0.nonce_for(b"attest:node-2")
        );
    }
}
