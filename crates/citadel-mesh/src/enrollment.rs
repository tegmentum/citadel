//! Enrollment and admission (design §7).
//!
//! A node does not become a member because an admin added it; it becomes a
//! member because it presents a bounded, attested identity claim and **a
//! quorum of the mesh accepts it**. The flow:
//!
//! 1. the mesh issues an [`EnrollmentChallenge`] (a fresh nonce + the PCRs to
//!    quote + the candidate's admission witnesses);
//! 2. the candidate answers with a signed [`EnrollmentClaim`] carrying a
//!    nonce-bound attestation quote;
//! 3. each admission witness verifies the claim (quote, nonce, measured
//!    state vs. the golden reference, and **duplicate-identity** detection)
//!    and casts a signed [`EnrollmentVote`];
//! 4. [`decide_admission`] tallies the votes — counting only *eligible*
//!    (trusted) witnesses — and admits the candidate on quorum.
//!
//! Admitted nodes start **probationary** (design §7.5): observed, but not yet
//! able to vote or anchor quorum decisions until they have attested cleanly
//! across a probation window.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::id::{MeshId, NodeId};
use crate::types::AttestationEvidence;

/// The mesh's challenge to a joining node (design §7.4 step 4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    pub mesh_id: MeshId,
    pub candidate: NodeId,
    pub nonce: Vec<u8>,
    pub pcr_bank: String,
    pub pcr_selection: Vec<u32>,
    pub policy_revision: u64,
    /// Witnesses assigned to verify this admission.
    pub admission_witnesses: Vec<NodeId>,
    /// Approving votes required from eligible witnesses.
    pub quorum_threshold: usize,
}

/// A joining node's signed identity claim (design §7.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentClaim {
    pub mesh_id: MeshId,
    pub candidate: NodeId,
    pub public_key: MeshPublicKey,
    /// Fingerprint of the candidate's attestation identity — the key used to
    /// spot a duplicate/cloned identity.
    pub ak_fingerprint: [u8; 32],
    pub claimed_role: String,
    pub agent_version: String,
    pub nonce: Vec<u8>,
    pub evidence: AttestationEvidence,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl EnrollmentClaim {
    #[allow(clippy::too_many_arguments)]
    fn signing_bytes(
        mesh_id: &MeshId,
        candidate: &NodeId,
        public_key: &MeshPublicKey,
        ak_fingerprint: &[u8; 32],
        claimed_role: &str,
        agent_version: &str,
        nonce: &[u8],
        evidence: &AttestationEvidence,
        timestamp_tick: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&(
            "enrollment-claim",
            mesh_id,
            candidate,
            public_key,
            ak_fingerprint,
            claimed_role,
            agent_version,
            nonce,
            evidence,
            timestamp_tick,
        ))
        .expect("serializable")
    }

    /// Build and self-sign a claim with the candidate's mesh keypair.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        kp: &MeshKeypair,
        mesh_id: MeshId,
        candidate: NodeId,
        ak_fingerprint: [u8; 32],
        claimed_role: impl Into<String>,
        agent_version: impl Into<String>,
        nonce: Vec<u8>,
        evidence: AttestationEvidence,
        timestamp_tick: u64,
    ) -> Self {
        let public_key = kp.public();
        let claimed_role = claimed_role.into();
        let agent_version = agent_version.into();
        let signature = kp.sign(&Self::signing_bytes(
            &mesh_id,
            &candidate,
            &public_key,
            &ak_fingerprint,
            &claimed_role,
            &agent_version,
            &nonce,
            &evidence,
            timestamp_tick,
        ));
        EnrollmentClaim {
            mesh_id,
            candidate,
            public_key,
            ak_fingerprint,
            claimed_role,
            agent_version,
            nonce,
            evidence,
            timestamp_tick,
            signature,
        }
    }

    /// Verify the claim is self-consistent: signed by the key it presents,
    /// and that key derives the claimed node id is left to the caller (it
    /// needs the mesh epoch/salt). Returns false on a bad signature.
    pub fn verify_signature(&self) -> bool {
        self.public_key.verify(
            &Self::signing_bytes(
                &self.mesh_id,
                &self.candidate,
                &self.public_key,
                &self.ak_fingerprint,
                &self.claimed_role,
                &self.agent_version,
                &self.nonce,
                &self.evidence,
                self.timestamp_tick,
            ),
            &self.signature,
        )
    }
}

/// A witness's admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionVerdict {
    Approve,
    Reject,
}

/// Why a witness voted as it did (design §8.4 reason-code style).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionReason {
    Ok,
    AttestationFailed,
    AkUntrusted,
    DuplicateIdentity,
    RoleNotAuthorized,
    NonceMismatch,
    BadSignature,
}

/// A witness's signed vote on a candidate (design §7.4 step 8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentVote {
    pub candidate: NodeId,
    pub witness: NodeId,
    pub verdict: AdmissionVerdict,
    pub reason: AdmissionReason,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl EnrollmentVote {
    fn signing_bytes(
        candidate: &NodeId,
        witness: &NodeId,
        verdict: AdmissionVerdict,
        reason: AdmissionReason,
        tick: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&("enrollment-vote", candidate, witness, verdict, reason, tick))
            .expect("serializable")
    }

    pub fn sign(
        kp: &MeshKeypair,
        witness: NodeId,
        candidate: NodeId,
        verdict: AdmissionVerdict,
        reason: AdmissionReason,
        timestamp_tick: u64,
    ) -> Self {
        let signature = kp.sign(&Self::signing_bytes(
            &candidate,
            &witness,
            verdict,
            reason,
            timestamp_tick,
        ));
        EnrollmentVote {
            candidate,
            witness,
            verdict,
            reason,
            timestamp_tick,
            signature,
        }
    }

    pub fn verify(&self, witness_pub: &MeshPublicKey) -> bool {
        witness_pub.verify(
            &Self::signing_bytes(
                &self.candidate,
                &self.witness,
                self.verdict,
                self.reason,
                self.timestamp_tick,
            ),
            &self.signature,
        )
    }
}

/// The outcome of tallying admission votes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionOutcome {
    pub admitted: bool,
    pub approvals: usize,
    pub rejections: usize,
    /// Distinct reasons among rejecting votes (e.g. `DuplicateIdentity`).
    pub reject_reasons: Vec<AdmissionReason>,
}

/// Tally admission votes, counting **only eligible** (trusted, assigned)
/// witnesses — a probationary or unknown node's vote does not count toward
/// admitting another node (design §7.5). Admits on `approvals >= threshold`.
pub fn decide_admission(
    votes: &[EnrollmentVote],
    eligible: &HashSet<NodeId>,
    threshold: usize,
) -> AdmissionOutcome {
    let mut approvals = 0usize;
    let mut rejections = 0usize;
    let mut reject_reasons = Vec::new();
    let mut counted: HashSet<NodeId> = HashSet::new();
    for v in votes {
        if !eligible.contains(&v.witness) || !counted.insert(v.witness) {
            continue; // ineligible voter, or duplicate vote from one witness
        }
        match v.verdict {
            AdmissionVerdict::Approve => approvals += 1,
            AdmissionVerdict::Reject => {
                rejections += 1;
                if !reject_reasons.contains(&v.reason) {
                    reject_reasons.push(v.reason);
                }
            }
        }
    }
    AdmissionOutcome {
        admitted: approvals >= threshold && threshold > 0,
        approvals,
        rejections,
        reject_reasons,
    }
}

/// Is `candidate_fingerprint` already present among existing members'
/// attestation fingerprints? A match is a cloned/duplicate identity
/// (design §7.4 "duplicate identity detection", §18.1 "TPM key cloning").
pub fn is_duplicate_identity(candidate_fingerprint: &[u8; 32], existing: &[[u8; 32]]) -> bool {
    existing.iter().any(|f| f == candidate_fingerprint)
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

    fn approve(witness: u8, candidate: u8) -> EnrollmentVote {
        EnrollmentVote::sign(&kp(witness), nid(witness), nid(candidate), AdmissionVerdict::Approve, AdmissionReason::Ok, 1)
    }
    fn reject(witness: u8, candidate: u8, reason: AdmissionReason) -> EnrollmentVote {
        EnrollmentVote::sign(&kp(witness), nid(witness), nid(candidate), AdmissionVerdict::Reject, reason, 1)
    }

    #[test]
    fn quorum_admits_only_with_enough_eligible_approvals() {
        let eligible: HashSet<NodeId> = [nid(1), nid(2), nid(3)].into_iter().collect();
        let votes = vec![approve(1, 9), approve(2, 9), reject(3, 9, AdmissionReason::Ok)];
        let outcome = decide_admission(&votes, &eligible, 2);
        assert!(outcome.admitted);
        assert_eq!(outcome.approvals, 2);
        assert_eq!(outcome.rejections, 1);
    }

    #[test]
    fn ineligible_probationary_votes_are_not_counted() {
        // Only nodes 1 and 2 are eligible (trusted); node 3 is probationary.
        let eligible: HashSet<NodeId> = [nid(1), nid(2)].into_iter().collect();
        // Node 3 tries to push the candidate over the line.
        let votes = vec![approve(1, 9), reject(2, 9, AdmissionReason::AttestationFailed), approve(3, 9)];
        let outcome = decide_admission(&votes, &eligible, 2);
        assert!(!outcome.admitted, "the probationary node's vote must not count");
        assert_eq!(outcome.approvals, 1);
    }

    #[test]
    fn duplicate_witness_votes_count_once() {
        let eligible: HashSet<NodeId> = [nid(1)].into_iter().collect();
        let votes = vec![approve(1, 9), approve(1, 9), approve(1, 9)];
        let outcome = decide_admission(&votes, &eligible, 2);
        assert_eq!(outcome.approvals, 1, "one witness, one vote");
        assert!(!outcome.admitted);
    }

    #[test]
    fn duplicate_identity_detection() {
        let existing = [[1u8; 32], [2u8; 32], [3u8; 32]];
        assert!(is_duplicate_identity(&[2u8; 32], &existing));
        assert!(!is_duplicate_identity(&[9u8; 32], &existing));
    }

    #[test]
    fn vote_and_claim_signatures_verify() {
        let v = approve(1, 9);
        assert!(v.verify(&kp(1).public()));
        assert!(!v.verify(&kp(2).public()));
    }
}
