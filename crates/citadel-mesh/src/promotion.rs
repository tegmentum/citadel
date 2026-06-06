//! Fleet quorum promotion of new measured states (design §10.3).
//!
//! A new boot state need not be blessed by a central authority. When a canary
//! boots an unrecognised state it is, at first, simply *unknown* (and so
//! distrusted). The state is promoted through the fleet:
//!
//! ```text
//! unknown → observed → staged → quorum-accepted → fleet-accepted
//! ```
//!
//! * **observed** — peers see the canary quoting a state their accepted set
//!   does not explain (`REFERENCE_UNKNOWN`).
//! * **staged** — a proposer puts the state forward with its provenance
//!   ([`PromotionProposal`]).
//! * **quorum-accepted** — eligible peers each **independently** judge the
//!   provenance against their own fleet artifact policy and vote
//!   ([`PromotionVote`]); [`decide_promotion`] admits it on quorum.
//! * **fleet-accepted** — every node adopts the state into the relevant
//!   profile's accepted set, so the canary (and its cohort) become trusted.
//!
//! This reuses the mesh's eligible-witness quorum (as enrollment and quarantine
//! do) rather than a single verifier declaring "known good".

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::id::NodeId;
use crate::reference::{ArtifactIdentity, Validity};

/// A proposal to accept a new measured state for a profile (design §10.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromotionProposal {
    pub id: [u8; 32],
    pub proposer: NodeId,
    /// Profile the state is proposed for (empty = the default profile).
    pub profile: String,
    pub index: u32,
    pub digest: Vec<u8>,
    /// Provenance peers judge — promotion requires it (you cannot vouch for an
    /// unattributed state).
    pub artifact: Option<ArtifactIdentity>,
    pub validity: Validity,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl PromotionProposal {
    #[allow(clippy::too_many_arguments)]
    fn content_id(
        proposer: &NodeId,
        profile: &str,
        index: u32,
        digest: &[u8],
        artifact: &Option<ArtifactIdentity>,
        validity: &Validity,
        timestamp_tick: u64,
    ) -> [u8; 32] {
        let bytes = serde_json::to_vec(&(
            "promotion-proposal",
            proposer,
            profile,
            index,
            digest,
            artifact,
            validity,
            timestamp_tick,
        ))
        .expect("serializable");
        *blake3::hash(&bytes).as_bytes()
    }

    /// Build and sign a proposal as `proposer`.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        kp: &MeshKeypair,
        proposer: NodeId,
        profile: impl Into<String>,
        index: u32,
        digest: Vec<u8>,
        artifact: Option<ArtifactIdentity>,
        validity: Validity,
        timestamp_tick: u64,
    ) -> Self {
        let profile = profile.into();
        let id = Self::content_id(&proposer, &profile, index, &digest, &artifact, &validity, timestamp_tick);
        let signature = kp.sign(&id);
        PromotionProposal {
            id,
            proposer,
            profile,
            index,
            digest,
            artifact,
            validity,
            timestamp_tick,
            signature,
        }
    }

    pub fn verify_signature(&self, proposer_pub: &MeshPublicKey) -> bool {
        let id = Self::content_id(
            &self.proposer,
            &self.profile,
            self.index,
            &self.digest,
            &self.artifact,
            &self.validity,
            self.timestamp_tick,
        );
        id == self.id && proposer_pub.verify(&self.id, &self.signature)
    }
}

/// An eligible peer's signed vote on a promotion proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromotionVote {
    pub proposal_id: [u8; 32],
    pub voter: NodeId,
    pub approve: bool,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl PromotionVote {
    fn signing_bytes(proposal_id: &[u8; 32], voter: &NodeId, approve: bool, tick: u64) -> Vec<u8> {
        serde_json::to_vec(&("promotion-vote", proposal_id, voter, approve, tick)).expect("serializable")
    }

    pub fn sign(kp: &MeshKeypair, voter: NodeId, proposal_id: [u8; 32], approve: bool, timestamp_tick: u64) -> Self {
        let signature = kp.sign(&Self::signing_bytes(&proposal_id, &voter, approve, timestamp_tick));
        PromotionVote { proposal_id, voter, approve, timestamp_tick, signature }
    }

    pub fn verify(&self, voter_pub: &MeshPublicKey) -> bool {
        voter_pub.verify(
            &Self::signing_bytes(&self.proposal_id, &self.voter, self.approve, self.timestamp_tick),
            &self.signature,
        )
    }
}

/// The outcome of tallying promotion votes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromotionOutcome {
    pub accepted: bool,
    pub approvals: usize,
    pub rejections: usize,
    pub required: usize,
}

/// Tally promotion votes, counting only **eligible** (trusted, assigned) voters
/// once each; admit on `approvals >= threshold` (design §10.3).
pub fn decide_promotion(
    proposal: &PromotionProposal,
    votes: &[PromotionVote],
    eligible: &HashSet<NodeId>,
    threshold: usize,
) -> PromotionOutcome {
    let mut approvals = 0usize;
    let mut rejections = 0usize;
    let mut counted: HashSet<NodeId> = HashSet::new();
    for v in votes {
        if v.proposal_id != proposal.id || !eligible.contains(&v.voter) || !counted.insert(v.voter) {
            continue;
        }
        if v.approve {
            approvals += 1;
        } else {
            rejections += 1;
        }
    }
    PromotionOutcome {
        accepted: threshold > 0 && approvals >= threshold,
        approvals,
        rejections,
        required: threshold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(n: u8) -> NodeId {
        NodeId([n; 32])
    }
    fn kp(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([n; 32])
    }

    fn proposal() -> PromotionProposal {
        PromotionProposal::create(&kp(1), nid(1), "prod", 4, b"k2".to_vec(), None, Validity::always(), 1)
    }

    fn vote(voter: u8, p: &PromotionProposal, approve: bool) -> PromotionVote {
        PromotionVote::sign(&kp(voter), nid(voter), p.id, approve, 2)
    }

    #[test]
    fn proposal_and_vote_signatures_verify() {
        let p = proposal();
        assert!(p.verify_signature(&kp(1).public()));
        assert!(!p.verify_signature(&kp(2).public()));
        let v = vote(3, &p, true);
        assert!(v.verify(&kp(3).public()));
    }

    #[test]
    fn quorum_of_eligible_approvals_accepts() {
        let p = proposal();
        let eligible: HashSet<NodeId> = (2..=6).map(nid).collect();
        let votes: Vec<PromotionVote> = (2..=4).map(|w| vote(w, &p, true)).collect();
        let outcome = decide_promotion(&p, &votes, &eligible, 3);
        assert!(outcome.accepted);
        assert_eq!(outcome.approvals, 3);
    }

    #[test]
    fn ineligible_and_duplicate_votes_do_not_count() {
        let p = proposal();
        let eligible: HashSet<NodeId> = [nid(2), nid(3)].into_iter().collect();
        // node 9 ineligible; node 2 votes twice.
        let votes = vec![vote(2, &p, true), vote(2, &p, true), vote(9, &p, true)];
        let outcome = decide_promotion(&p, &votes, &eligible, 2);
        assert_eq!(outcome.approvals, 1);
        assert!(!outcome.accepted);
    }

    #[test]
    fn rejections_block_acceptance() {
        let p = proposal();
        let eligible: HashSet<NodeId> = (2..=6).map(nid).collect();
        let votes: Vec<PromotionVote> = (2..=6).map(|w| vote(w, &p, false)).collect();
        let outcome = decide_promotion(&p, &votes, &eligible, 3);
        assert!(!outcome.accepted);
        assert_eq!(outcome.rejections, 5);
    }
}
