//! # citadel-facts (FL1) — witnessed fact/assertion ledger
//!
//! Attestation verdicts are one instance of a general pattern: the quorum
//! verifies a *checkable claim* and signs the result. This generalizes it — the
//! mesh reaches **signed quorum on any evidence-backed fact** (an SBOM hash,
//! "CVE-x is patched here", a config digest, a compliance control), turning it
//! into a hardware-rooted notary.
//!
//! Design calls: a fact is a typed, checkable claim + its evidence, and a witness
//! approves **only if it can independently check the evidence** (FL-C1 — the same
//! "verify, don't trust" stance as verdicts). The quorum + signing reuse the
//! release/verdict pattern (FL-C2); a signed fact carries a **beacon round** so
//! "patched" is current only as of that round (FL-C3, MB-bound). FL1 is the pure
//! core (assertion, checker, quorum attestation); FL2 wires it onto gossip + the
//! audit chain.

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};
use citadel_mesh::NodeId;
use serde::{Deserialize, Serialize};

/// A checkable claim about a subject, plus the evidence a witness checks it
/// against. The *fact* is `(subject, predicate, claim, beacon_round)`; `evidence`
/// is how a witness independently verifies it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assertion {
    pub subject: NodeId,
    /// What kind of fact (e.g. `sbom`, `patched:CVE-2024-1234`, `config`).
    pub predicate: String,
    /// The asserted value (e.g. the expected SBOM digest, or `patched`).
    pub claim: String,
    /// The beacon round the assertion is anchored to (freshness, FL-C3).
    pub beacon_round: u64,
    /// The evidence a checker verifies the claim against.
    pub evidence: Vec<u8>,
}

impl Assertion {
    /// The fact's identity — `BLAKE3` over `(subject, predicate, claim, round)`.
    /// Evidence is *not* in the id: witnesses each check their own evidence, but
    /// they vote on the same claim.
    pub fn id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"citadel-fact\x00");
        h.update(&self.subject.0);
        h.update(self.predicate.as_bytes());
        h.update(&[0]);
        h.update(self.claim.as_bytes());
        h.update(&self.beacon_round.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

/// Independently verify an assertion's claim against its evidence (FL-C1). A
/// witness approves only if its checker passes.
pub trait FactChecker {
    fn check(&self, assertion: &Assertion) -> bool;
}

/// An SBOM-digest checker: the claim must equal `BLAKE3(evidence)`.
pub struct SbomHashChecker;
impl FactChecker for SbomHashChecker {
    fn check(&self, a: &Assertion) -> bool {
        a.predicate == "sbom" && blake3::hash(&a.evidence).to_hex().to_string() == a.claim
    }
}

/// A patch checker: predicate `patched:<cve>`, claim `patched`, and the evidence
/// must mention the CVE.
pub struct PatchedChecker;
impl FactChecker for PatchedChecker {
    fn check(&self, a: &Assertion) -> bool {
        let Some(cve) = a.predicate.strip_prefix("patched:") else {
            return false;
        };
        a.claim == "patched" && String::from_utf8_lossy(&a.evidence).contains(cve)
    }
}

/// A witness's signed ballot on an assertion (APPROVE iff its checker passed),
/// bound to the fact id + the beacon round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactVote {
    pub assertion_id: [u8; 32],
    pub voter: NodeId,
    pub approve: bool,
    pub beacon_round: u64,
    pub signature: Signature,
}

impl FactVote {
    fn signing_bytes(
        assertion_id: &[u8; 32],
        voter: &NodeId,
        approve: bool,
        round: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&("citadel-fact-vote", assertion_id, voter, approve, round))
            .expect("serializable")
    }

    /// Independently check the assertion and cast a signed vote on the result.
    pub fn cast(
        kp: &MeshKeypair,
        assertion: &Assertion,
        voter: NodeId,
        checker: &dyn FactChecker,
        round: u64,
    ) -> Self {
        let assertion_id = assertion.id();
        let approve = checker.check(assertion);
        let signature = kp.sign(&Self::signing_bytes(&assertion_id, &voter, approve, round));
        FactVote {
            assertion_id,
            voter,
            approve,
            beacon_round: round,
            signature,
        }
    }

    pub fn verify(&self, voter_pub: &MeshPublicKey) -> bool {
        voter_pub.verify(
            &Self::signing_bytes(
                &self.assertion_id,
                &self.voter,
                self.approve,
                self.beacon_round,
            ),
            &self.signature,
        )
    }
}

/// The collected witness ballots on a fact — the signed attestation. A fact is
/// **witnessed true** when a quorum of eligible checkers approved it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactAttestation {
    pub assertion_id: [u8; 32],
    pub subject: NodeId,
    pub predicate: String,
    pub claim: String,
    pub beacon_round: u64,
    pub votes: Vec<FactVote>,
}

impl FactAttestation {
    /// Distinct **eligible** witnesses that validly approved this exact fact.
    /// Forged, uneligible, duplicate, or wrong-assertion votes don't count.
    pub fn approvals(&self, eligible: &[(NodeId, MeshPublicKey)]) -> usize {
        let mut counted = std::collections::HashSet::new();
        let mut n = 0;
        for v in &self.votes {
            let Some((_, pubkey)) = eligible.iter().find(|(id, _)| *id == v.voter) else {
                continue;
            };
            if v.assertion_id == self.assertion_id
                && v.approve
                && v.verify(pubkey)
                && counted.insert(v.voter)
            {
                n += 1;
            }
        }
        n
    }

    /// Is this fact witnessed true — a quorum of eligible checkers approved it?
    pub fn witnessed_true(&self, quorum: usize, eligible: &[(NodeId, MeshPublicKey)]) -> bool {
        self.approvals(eligible) >= quorum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }
    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn checkers_independently_verify_evidence() {
        let evidence = b"<sbom for svc-a>".to_vec();
        let sbom = Assertion {
            subject: node(7),
            predicate: "sbom".to_string(),
            claim: blake3::hash(&evidence).to_hex().to_string(),
            beacon_round: 100,
            evidence: evidence.clone(),
        };
        assert!(SbomHashChecker.check(&sbom), "evidence hashes to the claim");
        let forged = Assertion {
            claim: "0".repeat(64),
            ..sbom.clone()
        };
        assert!(
            !SbomHashChecker.check(&forged),
            "wrong digest fails the check"
        );

        let patch = Assertion {
            subject: node(7),
            predicate: "patched:CVE-2024-1234".to_string(),
            claim: "patched".to_string(),
            beacon_round: 100,
            evidence: b"applied fix for CVE-2024-1234 in kernel".to_vec(),
        };
        assert!(PatchedChecker.check(&patch));
        let unpatched = Assertion {
            evidence: b"nothing relevant".to_vec(),
            ..patch
        };
        assert!(!PatchedChecker.check(&unpatched));
    }

    #[test]
    fn a_quorum_of_checking_witnesses_attests_a_fact() {
        let witnesses: Vec<(NodeId, MeshKeypair)> = (10u8..=14).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> = witnesses
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect();
        let quorum = 3;

        let evidence = b"<sbom>".to_vec();
        let assertion = Assertion {
            subject: node(7),
            predicate: "sbom".to_string(),
            claim: blake3::hash(&evidence).to_hex().to_string(),
            beacon_round: 100,
            evidence,
        };

        // Every witness independently checks + votes; a quorum approve.
        let votes: Vec<FactVote> = witnesses
            .iter()
            .map(|(id, kp)| FactVote::cast(kp, &assertion, *id, &SbomHashChecker, 100))
            .collect();
        let att = FactAttestation {
            assertion_id: assertion.id(),
            subject: assertion.subject,
            predicate: assertion.predicate.clone(),
            claim: assertion.claim.clone(),
            beacon_round: 100,
            votes,
        };
        assert!(
            att.witnessed_true(quorum, &eligible),
            "checked fact is witnessed true"
        );

        // A false claim: witnesses' checkers reject it → no approvals → not true.
        let false_assertion = Assertion {
            claim: "1".repeat(64),
            ..assertion
        };
        let false_votes: Vec<FactVote> = witnesses
            .iter()
            .map(|(id, kp)| FactVote::cast(kp, &false_assertion, *id, &SbomHashChecker, 100))
            .collect();
        let false_att = FactAttestation {
            assertion_id: false_assertion.id(),
            subject: false_assertion.subject,
            predicate: false_assertion.predicate.clone(),
            claim: false_assertion.claim.clone(),
            beacon_round: 100,
            votes: false_votes,
        };
        assert_eq!(
            false_att.approvals(&eligible),
            0,
            "no witness can check a false claim"
        );
        assert!(!false_att.witnessed_true(quorum, &eligible));
    }

    #[test]
    fn forged_and_uneligible_votes_do_not_count() {
        let witnesses: Vec<(NodeId, MeshKeypair)> = (10u8..=12).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> = witnesses
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect();
        let evidence = b"x".to_vec();
        let a = Assertion {
            subject: node(7),
            predicate: "sbom".to_string(),
            claim: blake3::hash(&evidence).to_hex().to_string(),
            beacon_round: 100,
            evidence,
        };

        // A genuine vote, a duplicate of it, and a vote from a non-eligible voter.
        let (w0_id, w0_kp) = &witnesses[0];
        let genuine = FactVote::cast(w0_kp, &a, *w0_id, &SbomHashChecker, 100);
        let (out_id, out_kp) = idk(99);
        let outsider = FactVote::cast(&out_kp, &a, out_id, &SbomHashChecker, 100);
        let att = FactAttestation {
            assertion_id: a.id(),
            subject: a.subject,
            predicate: a.predicate,
            claim: a.claim,
            beacon_round: 100,
            votes: vec![genuine.clone(), genuine, outsider],
        };
        assert_eq!(
            att.approvals(&eligible),
            1,
            "duplicate + outsider don't add"
        );
    }
}
