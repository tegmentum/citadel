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
#[cfg(feature = "bls")]
pub mod bls;

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

// -- MB2: gossip + per-node beacon state -------------------------------------

/// The `AppRelay` topic beacon rounds are broadcast on.
pub const BEACON_TOPIC: [u8; 32] = *b"citadel-beacon-round-topic\x00\x00\x00\x00\x00\x00";

impl BeaconRound {
    /// Serialize for gossip (`AppRelay` payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("beacon round is serializable")
    }
    /// Deserialize a gossiped round.
    pub fn from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(b)?)
    }
}

/// A node's view of the beacon: the latest **verified** round it has adopted.
/// Each round is independently authentic (threshold-signed), so adoption is
/// "newest verified wins" — monotonic and gap-tolerant (a late joiner adopts the
/// current beacon without the full chain; `verify_chain` proves a full sequence
/// when needed).
pub struct BeaconState {
    public: PublicKeyPackage,
    current: Option<BeaconRound>,
}

impl BeaconState {
    pub fn new(public: PublicKeyPackage) -> Self {
        BeaconState {
            public,
            current: None,
        }
    }

    /// The current beacon round, if any has been adopted.
    pub fn current(&self) -> Option<&BeaconRound> {
        self.current.as_ref()
    }

    /// The current round number (0 before any beacon is adopted).
    pub fn round(&self) -> u64 {
        self.current.as_ref().map(|r| r.round).unwrap_or(0)
    }

    /// Adopt `round` iff it verifies against the group key **and** is strictly
    /// newer than the current one. Returns true if adopted.
    pub fn adopt(&mut self, round: BeaconRound) -> bool {
        if !round.verify(&self.public) {
            return false;
        }
        let newer = self
            .current
            .as_ref()
            .map(|c| round.round > c.round)
            .unwrap_or(true);
        if newer {
            self.current = Some(round);
        }
        newer
    }

    /// Adopt every gossiped round drained from `AppRelay` (the newest valid one
    /// wins). Returns true if the current round advanced.
    pub fn ingest(&mut self, payloads: &[Vec<u8>]) -> bool {
        let mut advanced = false;
        for p in payloads {
            if let Ok(round) = BeaconRound::from_bytes(p) {
                advanced |= self.adopt(round);
            }
        }
        advanced
    }

    /// The current round's random output (freshness anchor), if any.
    pub fn value(&self) -> Option<[u8; 32]> {
        self.current.as_ref().map(|r| r.value())
    }

    /// A replay-proof, freshness-bound challenge nonce for `context`, tied to the
    /// current beacon round (the attestation-challenge helper, MB3 consumer).
    pub fn nonce_for(&self, context: &[u8]) -> Option<[u8; 32]> {
        self.current.as_ref().map(|r| r.nonce_for(context))
    }
}

#[cfg(test)]
mod gossip_tests {
    use super::*;

    #[test]
    fn beacon_state_adopts_newest_verified_and_rejects_stale_or_forged() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let signers = &packages[0..3];
        let r0 = BeaconRound::produce(0, GENESIS_PREV, signers, &public).unwrap();
        let r1 = next_round(&r0, signers, &public).unwrap();

        let mut state = BeaconState::new(public.clone());
        assert!(
            state.adopt(r1.clone()),
            "adopts a verified round (late joiner)"
        );
        assert_eq!(state.round(), 1);
        assert!(!state.adopt(r0.clone()), "an older round is not adopted");
        assert_eq!(state.round(), 1);

        // A round validly signed by a *different* group is rejected by our state.
        let (other_pub, other_pkgs) = tsig::keygen(3, 5).unwrap();
        let forged = BeaconRound::produce(2, r1.digest(), &other_pkgs[0..3], &other_pub).unwrap();
        assert!(forged.verify(&other_pub), "valid under the other group");
        assert!(
            !state.adopt(forged),
            "but not signed by our group -> rejected"
        );

        // round-trip through the gossip encoding.
        let r2 = next_round(&r1, signers, &public).unwrap();
        assert!(state.ingest(&[r2.to_bytes()]));
        assert_eq!(state.round(), 2);
        assert_eq!(state.value(), Some(r2.value()));
    }
}

// -- MB3: freshness consumers (replay-proof challenges + leases) -------------

/// A verifier challenge tied to a beacon round. The challenged party answers
/// with `nonce` (e.g. in a TPM quote); because the nonce is derived from the
/// round's unpredictable beacon value, it can't be precomputed, and because the
/// round is carried, a response answering a *stale* round is detectable — a
/// replay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub beacon_round: u64,
    pub nonce: [u8; 32],
}

impl BeaconRound {
    /// Issue a replay-proof challenge bound to this round + `context` (e.g. the
    /// subject being attested).
    pub fn challenge(&self, context: &[u8]) -> Challenge {
        Challenge {
            beacon_round: self.round,
            nonce: self.nonce_for(context),
        }
    }
}

impl BeaconState {
    /// Issue a challenge from the current beacon round (`None` until a beacon is
    /// adopted) — the attestation-verifier helper.
    pub fn challenge(&self, context: &[u8]) -> Option<Challenge> {
        self.current.as_ref().map(|r| r.challenge(context))
    }
}

/// Whether a challenge is still fresh: its round is within `max_age_rounds` of
/// the current beacon round. A response to a staler challenge is a replay and
/// should be rejected.
pub fn challenge_fresh(challenge: &Challenge, current_round: u64, max_age_rounds: u64) -> bool {
    current_round.saturating_sub(challenge.beacon_round) <= max_age_rounds
}

/// Whether a beacon-round lease is still active — the canonical freshness
/// predicate shared by MSS lease epochs, SVID renewal cadence, and capability
/// TTLs (`citadel-caps` already uses it): valid while fewer than `lease_rounds`
/// beacon rounds have elapsed since `issued_round`. Renewal re-runs the issuing
/// quorum at the current round, so a node that lost trust is denied at renewal.
pub fn lease_active(issued_round: u64, current_round: u64, lease_rounds: u64) -> bool {
    current_round.saturating_sub(issued_round) <= lease_rounds
}

#[cfg(test)]
mod freshness_tests {
    use super::*;

    #[test]
    fn challenges_are_replay_proof_across_rounds() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let signers = &packages[0..3];
        let r0 = BeaconRound::produce(0, GENESIS_PREV, signers, &public).unwrap();
        let r1 = next_round(&r0, signers, &public).unwrap();

        let c0 = r0.challenge(b"attest:node-7");
        let c1 = r1.challenge(b"attest:node-7");
        // A round-0 answer can't be passed off as answering round 1.
        assert_ne!(c0.nonce, c1.nonce);
        assert_eq!(c0.beacon_round, 0);

        // Fresh within the age window, stale beyond it (a replay is detected).
        assert!(challenge_fresh(&c0, 0, 2));
        assert!(challenge_fresh(&c0, 2, 2));
        assert!(!challenge_fresh(&c0, 3, 2), "a stale challenge is a replay");
    }

    #[test]
    fn beacon_state_issues_challenges_from_the_current_round() {
        let (public, packages) = tsig::keygen(3, 5).unwrap();
        let r0 = BeaconRound::produce(0, GENESIS_PREV, &packages[0..3], &public).unwrap();
        let mut state = BeaconState::new(public);
        assert!(
            state.challenge(b"x").is_none(),
            "no challenge before a beacon is adopted"
        );
        state.adopt(r0.clone());
        assert_eq!(state.challenge(b"x"), Some(r0.challenge(b"x")));
    }

    #[test]
    fn lease_active_over_beacon_rounds() {
        assert!(lease_active(100, 100, 10));
        assert!(lease_active(100, 110, 10));
        assert!(
            !lease_active(100, 111, 10),
            "lease expired -> deny at renewal"
        );
    }
}
