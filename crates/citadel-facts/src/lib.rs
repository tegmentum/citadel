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

// -- FL2: gossip + the queryable fact ledger ---------------------------------

/// A fact-protocol message gossiped between nodes: an assertion to be checked, or
/// a witness's vote on one (reuses the verdict gossip path).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FactMessage {
    Assert(Assertion),
    Vote(FactVote),
}

/// The `AppRelay` topic the fact protocol runs on.
pub const FACT_TOPIC: [u8; 32] = *b"citadel-fact-protocol-topic\x00\x00\x00\x00\x00";

impl FactMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fact message is serializable")
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

/// A ledger of facts the mesh has witnessed true — the queryable notary surface.
/// (FL2 keeps it in memory; FL3 appends to the durable audit chain and exposes a
/// control-plane API.)
#[derive(Default)]
pub struct FactLedger {
    facts: Vec<FactAttestation>,
}

impl FactLedger {
    pub fn new() -> Self {
        FactLedger::default()
    }

    /// Record an attestation **iff** it is witnessed true by a quorum of eligible
    /// checkers. Returns whether it was recorded.
    pub fn record(
        &mut self,
        attestation: FactAttestation,
        quorum: usize,
        eligible: &[(NodeId, MeshPublicKey)],
    ) -> bool {
        if attestation.witnessed_true(quorum, eligible) {
            self.facts.push(attestation);
            true
        } else {
            false
        }
    }

    /// Is there a witnessed fact for this subject + predicate?
    pub fn is_witnessed(&self, subject: NodeId, predicate: &str) -> bool {
        self.facts
            .iter()
            .any(|f| f.subject == subject && f.predicate == predicate)
    }

    /// The fleet-unanimity query: does **every** listed subject have a witnessed
    /// fact for `predicate`? (e.g. "is the whole fleet patched for CVE-X?")
    pub fn fleet_satisfies(&self, predicate: &str, subjects: &[NodeId]) -> bool {
        !subjects.is_empty() && subjects.iter().all(|s| self.is_witnessed(*s, predicate))
    }

    pub fn facts(&self) -> &[FactAttestation] {
        &self.facts
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }
    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    // A witnessed "patched" attestation for `subject`, by a quorum of `witnesses`.
    fn patched_attestation(
        subject: NodeId,
        cve: &str,
        witnesses: &[(NodeId, MeshKeypair)],
        round: u64,
    ) -> FactAttestation {
        let a = Assertion {
            subject,
            predicate: format!("patched:{cve}"),
            claim: "patched".to_string(),
            beacon_round: round,
            evidence: format!("applied fix for {cve}").into_bytes(),
        };
        let votes = witnesses
            .iter()
            .map(|(id, kp)| FactVote::cast(kp, &a, *id, &PatchedChecker, round))
            .collect();
        FactAttestation {
            assertion_id: a.id(),
            subject,
            predicate: a.predicate,
            claim: a.claim,
            beacon_round: round,
            votes,
        }
    }

    #[test]
    fn gossip_message_round_trips() {
        let a = Assertion {
            subject: node(7),
            predicate: "sbom".to_string(),
            claim: "x".to_string(),
            beacon_round: 1,
            evidence: vec![1, 2, 3],
        };
        let m = FactMessage::Assert(a);
        let back = FactMessage::from_bytes(&m.to_bytes()).unwrap();
        assert!(matches!(back, FactMessage::Assert(_)));
    }

    #[test]
    fn ledger_records_witnessed_facts_and_answers_fleet_queries() {
        let witnesses: Vec<(NodeId, MeshKeypair)> = (10u8..=14).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> = witnesses
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect();
        let quorum = 3;
        let cve = "CVE-2024-1234";
        let fleet = [node(1), node(2), node(3)];

        let mut ledger = FactLedger::new();
        for &s in &fleet {
            assert!(ledger.record(
                patched_attestation(s, cve, &witnesses, 100),
                quorum,
                &eligible
            ));
        }
        // The whole fleet is witnessed patched.
        assert!(ledger.fleet_satisfies(&format!("patched:{cve}"), &fleet));
        // A subject with no recorded fact breaks unanimity.
        assert!(!ledger.fleet_satisfies(&format!("patched:{cve}"), &[node(1), node(2), node(9)]));

        // A *false* attestation (witnesses can't check it) is not recorded.
        let false_att = FactAttestation {
            assertion_id: [0u8; 32],
            subject: node(4),
            predicate: format!("patched:{cve}"),
            claim: "patched".to_string(),
            beacon_round: 100,
            // votes for a different assertion id → zero approvals for this one
            votes: vec![],
        };
        assert!(!ledger.record(false_att, quorum, &eligible));
        assert!(!ledger.is_witnessed(node(4), &format!("patched:{cve}")));
    }
}

// -- FL3 (in-tree slice): the citadel:fact-<k> selector + fleet rollup --------
//
// The control-plane API + dashboard panel are deployment; the policy selector and
// the rollup query are in-tree and testable here.

/// The policy selector a witnessed fact grants — e.g. a SPIRE registration entry
/// can require `citadel:fact-patched:CVE-2024-1234`, so a workload only lands on a
/// node the mesh has witnessed as patched (mirrors the `citadel:tpm-spec` selector).
pub fn fact_selector(predicate: &str) -> String {
    format!("citadel:fact-{predicate}")
}

/// A fleet-wide summary of who is witnessed for a predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetRollup {
    pub predicate: String,
    pub witnessed: usize,
    pub total: usize,
}

impl FleetRollup {
    /// Every listed subject is witnessed for the predicate.
    pub fn unanimous(&self) -> bool {
        self.total > 0 && self.witnessed == self.total
    }
}

impl FactLedger {
    /// The `citadel:fact-<predicate>` selectors a subject's witnessed facts grant.
    pub fn selectors_for(&self, subject: NodeId) -> Vec<String> {
        let mut sels: Vec<String> = self
            .facts
            .iter()
            .filter(|f| f.subject == subject)
            .map(|f| fact_selector(&f.predicate))
            .collect();
        sels.sort();
        sels.dedup();
        sels
    }

    /// Roll up how many of `subjects` are witnessed for `predicate`.
    pub fn fleet_rollup(&self, predicate: &str, subjects: &[NodeId]) -> FleetRollup {
        let witnessed = subjects
            .iter()
            .filter(|s| self.is_witnessed(**s, predicate))
            .count();
        FleetRollup {
            predicate: predicate.to_string(),
            witnessed,
            total: subjects.len(),
        }
    }
}

#[cfg(test)]
mod fl3_tests {
    use super::*;

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }
    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn patched(subject: NodeId, cve: &str, ws: &[(NodeId, MeshKeypair)]) -> FactAttestation {
        let a = Assertion {
            subject,
            predicate: format!("patched:{cve}"),
            claim: "patched".to_string(),
            beacon_round: 100,
            evidence: format!("fix for {cve}").into_bytes(),
        };
        let votes = ws
            .iter()
            .map(|(id, kp)| FactVote::cast(kp, &a, *id, &PatchedChecker, 100))
            .collect();
        FactAttestation {
            assertion_id: a.id(),
            subject,
            predicate: a.predicate,
            claim: a.claim,
            beacon_round: 100,
            votes,
        }
    }

    #[test]
    fn witnessed_facts_grant_selectors_and_roll_up() {
        let ws: Vec<(NodeId, MeshKeypair)> = (10u8..=14).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> =
            ws.iter().map(|(id, kp)| (*id, kp.public())).collect();
        let cve = "CVE-2024-1234";
        let mut ledger = FactLedger::new();
        ledger.record(patched(node(1), cve, &ws), 3, &eligible);
        ledger.record(patched(node(2), cve, &ws), 3, &eligible);

        // node 1 grants the fact selector; node 3 (no fact) grants nothing.
        assert_eq!(
            ledger.selectors_for(node(1)),
            vec![fact_selector(&format!("patched:{cve}"))]
        );
        assert!(ledger.selectors_for(node(3)).is_empty());

        // The fleet rollup: 2 of 3 witnessed → not unanimous.
        let rollup = ledger.fleet_rollup(&format!("patched:{cve}"), &[node(1), node(2), node(3)]);
        assert_eq!(
            rollup,
            FleetRollup {
                predicate: format!("patched:{cve}"),
                witnessed: 2,
                total: 3
            }
        );
        assert!(!rollup.unanimous());
        assert!(ledger
            .fleet_rollup(&format!("patched:{cve}"), &[node(1), node(2)])
            .unanimous());
    }
}

// -- P3: fact protocol over the live mesh (AppRelay) --------------------------

/// A witness's reaction to gossiped fact messages (FL live): check each gossiped
/// assertion with `checker` and return the votes to broadcast. The flow mirrors
/// TW2 — a node broadcasts `FactMessage::Assert` on [`FACT_TOPIC`]; each witness
/// runs this and re-broadcasts the votes; a collector aggregates them.
pub fn witness_gossiped_assertions(
    payloads: &[Vec<u8>],
    kp: &MeshKeypair,
    voter: NodeId,
    checker: &dyn FactChecker,
    round: u64,
) -> Vec<FactVote> {
    payloads
        .iter()
        .filter_map(|p| FactMessage::from_bytes(p))
        .filter_map(|m| match m {
            FactMessage::Assert(a) => Some(FactVote::cast(kp, &a, voter, checker, round)),
            FactMessage::Vote(_) => None,
        })
        .collect()
}

/// Collect the [`FactVote`]s out of gossiped fact messages (the collector side).
pub fn votes_from_gossip(payloads: &[Vec<u8>]) -> Vec<FactVote> {
    payloads
        .iter()
        .filter_map(|p| FactMessage::from_bytes(p))
        .filter_map(|m| match m {
            FactMessage::Vote(v) => Some(v),
            FactMessage::Assert(_) => None,
        })
        .collect()
}
