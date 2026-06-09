//! Quorum-driven, reversible quarantine (design §13).
//!
//! Isolating a node is never a unilateral act: a peer *proposes* a
//! quarantine at a given [`QuarantineScope`], the subject's witnesses *vote*,
//! and the action is enacted only if enough **eligible** witnesses approve —
//! with the most severe scopes additionally gated on an **operator**
//! approval. Quarantine is reversible: an isolated node rejoins by attesting
//! afresh and being voted back in (to probation, never straight to trusted).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::id::NodeId;
use crate::types::ReasonCode;

/// How much a quarantine restricts a node, least to most severe
/// (design §13.2). Higher scopes need broader agreement to enact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineScope {
    /// Watch more closely; no restriction yet.
    ObserveOnly,
    /// May not vote on mesh decisions (enrollment/quarantine).
    RestrictMeshVoting,
    /// May not hold evidence fragments.
    RestrictEvidenceHolding,
    /// May not be scheduled new workloads.
    BlockWorkloadScheduling,
    /// Cut off from the network.
    NetworkIsolate,
    /// Revoke its credentials.
    CredentialRevoke,
    /// Full isolation.
    FullIsolation,
}

impl QuarantineScope {
    /// Severity rank (0 = least, 6 = most).
    pub fn severity(&self) -> u8 {
        match self {
            QuarantineScope::ObserveOnly => 0,
            QuarantineScope::RestrictMeshVoting => 1,
            QuarantineScope::RestrictEvidenceHolding => 2,
            QuarantineScope::BlockWorkloadScheduling => 3,
            QuarantineScope::NetworkIsolate => 4,
            QuarantineScope::CredentialRevoke => 5,
            QuarantineScope::FullIsolation => 6,
        }
    }

    /// At/above this scope the node loses its vote on mesh decisions.
    pub fn restricts_voting(&self) -> bool {
        self.severity() >= QuarantineScope::RestrictMeshVoting.severity()
    }

    /// At/above this scope the node may no longer be assigned evidence
    /// fragments to hold — it is excluded from the durable-evidence holder set.
    pub fn restricts_evidence_holding(&self) -> bool {
        self.severity() >= QuarantineScope::RestrictEvidenceHolding.severity()
    }

    /// At/above this scope the node is effectively isolated from the mesh.
    pub fn isolates(&self) -> bool {
        self.severity() >= QuarantineScope::NetworkIsolate.severity()
    }

    /// At/above this scope new workloads may not be scheduled on the target —
    /// the enforcement behind an app-scoped `BlockWorkloadScheduling` response
    /// (`application-appraisal.md` §5.2).
    pub fn blocks_workload_scheduling(&self) -> bool {
        self.severity() >= QuarantineScope::BlockWorkloadScheduling.severity()
    }

    /// At/above this scope the target's mesh-issued credentials are revoked —
    /// the enforcement behind an app-scoped `CredentialRevoke` response.
    pub fn revokes_credentials(&self) -> bool {
        self.severity() >= QuarantineScope::CredentialRevoke.severity()
    }

    /// What it takes to enact this scope over `witness_count` witnesses
    /// (design §13.4): a fraction of the witnesses, escalating with
    /// severity, plus an operator sign-off for the most destructive scopes.
    pub fn requirement(&self, witness_count: usize) -> Requirement {
        // Fraction of assigned witnesses that must approve.
        let frac = match self {
            QuarantineScope::ObserveOnly => 0.2,
            QuarantineScope::RestrictMeshVoting => 0.5,
            QuarantineScope::RestrictEvidenceHolding => 0.5,
            QuarantineScope::BlockWorkloadScheduling => 0.6,
            QuarantineScope::NetworkIsolate => 0.7,
            QuarantineScope::CredentialRevoke => 0.7,
            QuarantineScope::FullIsolation => 0.8,
        };
        let approvals_needed = ((frac * witness_count as f64).ceil() as usize).max(1);
        // The most destructive scopes require an operator, not witnesses alone.
        let operator_required = matches!(
            self,
            QuarantineScope::CredentialRevoke | QuarantineScope::FullIsolation
        );
        Requirement {
            approvals_needed,
            operator_required,
        }
    }
}

/// What enacting a scope demands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub approvals_needed: usize,
    pub operator_required: bool,
}

/// A proposal to quarantine `subject` at `scope` (design §13.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineProposal {
    pub id: [u8; 32],
    pub subject: NodeId,
    pub proposer: NodeId,
    pub reason_codes: Vec<ReasonCode>,
    pub scope: QuarantineScope,
    pub expires_at_tick: u64,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl QuarantineProposal {
    fn content_id(
        subject: &NodeId,
        proposer: &NodeId,
        reason_codes: &[ReasonCode],
        scope: QuarantineScope,
        expires_at_tick: u64,
        timestamp_tick: u64,
    ) -> [u8; 32] {
        let bytes = serde_json::to_vec(&(
            "quarantine-proposal",
            subject,
            proposer,
            reason_codes,
            scope,
            expires_at_tick,
            timestamp_tick,
        ))
        .expect("serializable");
        *blake3::hash(&bytes).as_bytes()
    }

    /// Build and sign a proposal as `proposer`.
    pub fn create(
        kp: &MeshKeypair,
        proposer: NodeId,
        subject: NodeId,
        reason_codes: Vec<ReasonCode>,
        scope: QuarantineScope,
        expires_at_tick: u64,
        timestamp_tick: u64,
    ) -> Self {
        let id = Self::content_id(
            &subject,
            &proposer,
            &reason_codes,
            scope,
            expires_at_tick,
            timestamp_tick,
        );
        let signature = kp.sign(&id);
        QuarantineProposal {
            id,
            subject,
            proposer,
            reason_codes,
            scope,
            expires_at_tick,
            timestamp_tick,
            signature,
        }
    }

    pub fn verify_signature(&self, proposer_pub: &MeshPublicKey) -> bool {
        let id = Self::content_id(
            &self.subject,
            &self.proposer,
            &self.reason_codes,
            self.scope,
            self.expires_at_tick,
            self.timestamp_tick,
        );
        id == self.id && proposer_pub.verify(&self.id, &self.signature)
    }
}

/// A witness's ballot on a proposal (design §13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ballot {
    Approve,
    Reject,
    Abstain,
}

/// A signed vote on a quarantine proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineVote {
    pub proposal_id: [u8; 32],
    pub voter: NodeId,
    pub ballot: Ballot,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl QuarantineVote {
    fn signing_bytes(proposal_id: &[u8; 32], voter: &NodeId, ballot: Ballot, tick: u64) -> Vec<u8> {
        serde_json::to_vec(&("quarantine-vote", proposal_id, voter, ballot, tick))
            .expect("serializable")
    }

    pub fn sign(
        kp: &MeshKeypair,
        voter: NodeId,
        proposal_id: [u8; 32],
        ballot: Ballot,
        timestamp_tick: u64,
    ) -> Self {
        let signature = kp.sign(&Self::signing_bytes(
            &proposal_id,
            &voter,
            ballot,
            timestamp_tick,
        ));
        QuarantineVote {
            proposal_id,
            voter,
            ballot,
            timestamp_tick,
            signature,
        }
    }

    pub fn verify(&self, voter_pub: &MeshPublicKey) -> bool {
        voter_pub.verify(
            &Self::signing_bytes(
                &self.proposal_id,
                &self.voter,
                self.ballot,
                self.timestamp_tick,
            ),
            &self.signature,
        )
    }
}

/// A trusted operator's signed approval of a quarantine proposal — the operator
/// sign-off the most severe scopes require (§13.4). Relayed into the mesh by the
/// control plane (CP5); a node honours it only from a key it trusts as an
/// operator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorQuarantineApproval {
    pub proposal_id: [u8; 32],
    pub operator: MeshPublicKey,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl OperatorQuarantineApproval {
    fn signing_bytes(proposal_id: &[u8; 32], tick: u64) -> Vec<u8> {
        serde_json::to_vec(&("quarantine-operator-approval", proposal_id, tick))
            .expect("serializable")
    }

    /// Sign an approval of `proposal_id` as the operator.
    pub fn sign(operator: &MeshKeypair, proposal_id: [u8; 32], timestamp_tick: u64) -> Self {
        let signature = operator.sign(&Self::signing_bytes(&proposal_id, timestamp_tick));
        OperatorQuarantineApproval {
            proposal_id,
            operator: operator.public(),
            timestamp_tick,
            signature,
        }
    }

    /// Verify the operator's signature over `(proposal_id, tick)`.
    pub fn verify(&self) -> bool {
        self.operator.verify(
            &Self::signing_bytes(&self.proposal_id, self.timestamp_tick),
            &self.signature,
        )
    }
}

/// The outcome of a quarantine vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuarantineDecision {
    pub enacted: bool,
    pub scope: QuarantineScope,
    pub approvals: usize,
    pub required: usize,
    pub operator_required: bool,
    pub operator_approved: bool,
}

/// Tally a quarantine vote: count `Approve` ballots from **eligible**
/// witnesses (one each), and enact only if approvals meet the scope's
/// requirement *and* any required operator approval is present (design §13.4).
pub fn decide_quarantine(
    proposal: &QuarantineProposal,
    votes: &[QuarantineVote],
    eligible: &HashSet<NodeId>,
    witness_count: usize,
    operator_approved: bool,
) -> QuarantineDecision {
    let req = proposal.scope.requirement(witness_count);
    let mut counted: HashSet<NodeId> = HashSet::new();
    let mut approvals = 0usize;
    for v in votes {
        if v.proposal_id != proposal.id || !eligible.contains(&v.voter) || !counted.insert(v.voter)
        {
            continue;
        }
        if matches!(v.ballot, Ballot::Approve) {
            approvals += 1;
        }
    }
    let enacted =
        approvals >= req.approvals_needed && (!req.operator_required || operator_approved);
    QuarantineDecision {
        enacted,
        scope: proposal.scope,
        approvals,
        required: req.approvals_needed,
        operator_required: req.operator_required,
        operator_approved,
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

    fn proposal(scope: QuarantineScope) -> QuarantineProposal {
        QuarantineProposal::create(
            &kp(1),
            nid(1),
            nid(9),
            vec![ReasonCode::PcrMismatch],
            scope,
            100,
            1,
        )
    }

    fn vote(witness: u8, p: &QuarantineProposal, ballot: Ballot) -> QuarantineVote {
        QuarantineVote::sign(&kp(witness), nid(witness), p.id, ballot, 2)
    }

    #[test]
    fn proposal_and_vote_signatures_verify() {
        let p = proposal(QuarantineScope::RestrictMeshVoting);
        assert!(p.verify_signature(&kp(1).public()));
        assert!(!p.verify_signature(&kp(2).public()));
        let v = vote(3, &p, Ballot::Approve);
        assert!(v.verify(&kp(3).public()));
    }

    #[test]
    fn lighter_scope_enacts_on_majority() {
        // 5 witnesses, RestrictMeshVoting needs ceil(0.5*5)=3.
        let p = proposal(QuarantineScope::RestrictMeshVoting);
        let eligible: HashSet<NodeId> = (2..=6).map(nid).collect();
        let votes: Vec<QuarantineVote> = (2..=4).map(|w| vote(w, &p, Ballot::Approve)).collect();
        let d = decide_quarantine(&p, &votes, &eligible, 5, false);
        assert!(d.enacted);
        assert_eq!(d.required, 3);
    }

    #[test]
    fn full_isolation_needs_more_and_an_operator() {
        let eligible: HashSet<NodeId> = (2..=6).map(nid).collect();
        // Five approvals for FullIsolation (needs ceil(0.8*5)=4) — but no
        // operator approval, so it is NOT enacted.
        let p = proposal(QuarantineScope::FullIsolation);
        let votes: Vec<QuarantineVote> = (2..=6).map(|w| vote(w, &p, Ballot::Approve)).collect();
        let d = decide_quarantine(&p, &votes, &eligible, 5, false);
        assert!(!d.enacted, "witness votes alone cannot fully isolate");
        assert!(d.operator_required);

        // With the operator's approval, it enacts.
        let d = decide_quarantine(&p, &votes, &eligible, 5, true);
        assert!(d.enacted);
    }

    #[test]
    fn ineligible_voters_do_not_count() {
        let p = proposal(QuarantineScope::RestrictMeshVoting);
        // Only one eligible witness; the rest are ineligible (e.g. themselves
        // quarantined / probationary).
        let eligible: HashSet<NodeId> = [nid(2)].into_iter().collect();
        let votes: Vec<QuarantineVote> = (2..=5).map(|w| vote(w, &p, Ballot::Approve)).collect();
        let d = decide_quarantine(&p, &votes, &eligible, 5, false);
        assert_eq!(d.approvals, 1);
        assert!(!d.enacted);
    }
}
