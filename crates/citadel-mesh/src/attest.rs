//! The attestation evidence path, over a [`tpm_core`] TPM backend.
//!
//! A node is both an **attester** (it quotes its own PCRs when challenged)
//! and a **verifier** (it checks peers' evidence against its own reference
//! state). [`Attestor`] wraps the node's TPM backend and provides both
//! directions, reusing `backend.quote` / `backend.verify_quote`.
//!
//! A verifier checks a peer's evidence in two parts:
//!
//! * **signature + nonce** — `backend.verify_quote` confirms the quote is a
//!   genuine, freshly-nonce-bound signature under the evidence's AK;
//! * **measured state** — the quoted PCRs are compared against a
//!   [`ReferenceMeasurements`] golden (the Reference Value Provider role,
//!   design §3, §14.2), *not* against the verifier's own PCRs. This is the
//!   Phase 1 correction: a verifier need not be in the same state as its
//!   subject, so heterogeneous machines can witness each other.
//!
//! Phase 0/1 uses [`tpm_core::backend::MockBackend`] for unit tests and the
//! real vTPM backend behind the same `Box<dyn TpmBackend>` seam for the
//! hardware acceptance test. A node whose PCRs diverge from the reference
//! (a stand-in for tamper / an un-approved upgrade) is independently flagged
//! `PCR_MISMATCH` by every witness.

use std::collections::{BTreeMap, HashSet};

use tpm_core::backend::{KeyHandle, PcrValue, TpmBackend};
use tpm_core::model::Algorithm;

use crate::crypto::MeshPublicKey;
use crate::id::NodeId;
use crate::reference::{
    AcceptedReferences, PcrClass, ReferenceMatchPolicy, ReferenceOutcome, RetiredAction,
};
use crate::types::{
    AttestationChallenge, AttestationEvidence, AttestationResult, Endorsement, ReasonCode, Verdict,
};

/// The set of endorsers a verifier trusts to vouch for attestation keys (the
/// RATS *Endorser* role: hardware EK / manufacturer / operator roots). When
/// non-empty, a quote is accepted only if its AK carries an [`Endorsement`]
/// from one of these — otherwise `AK_UNTRUSTED`. Empty = endorsement not
/// required (self-certifying AK, as in the early phases).
#[derive(Clone, Debug, Default)]
pub struct TrustAnchors {
    endorsers: HashSet<MeshPublicKey>,
}

impl TrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    /// A set trusting a single endorser.
    pub fn with(endorser: MeshPublicKey) -> Self {
        let mut s = HashSet::new();
        s.insert(endorser);
        TrustAnchors { endorsers: s }
    }

    pub fn trust(&mut self, endorser: MeshPublicKey) {
        self.endorsers.insert(endorser);
    }

    pub fn is_empty(&self) -> bool {
        self.endorsers.is_empty()
    }

    pub fn trusts(&self, endorser: &MeshPublicKey) -> bool {
        self.endorsers.contains(endorser)
    }
}

/// Expected PCR digests for a known-good measured state — the reference a
/// verifier matches a subject's quote against (design §14.2). In a full
/// deployment these come from the signed policy / golden-image registry; in
/// tests they are captured from a known-good node.
#[derive(Clone, Debug, Default)]
pub struct ReferenceMeasurements {
    pub bank: String,
    /// PCR index → expected digest.
    pub pcrs: BTreeMap<u32, Vec<u8>>,
}

impl ReferenceMeasurements {
    /// Build a reference from a set of PCR values (e.g. read from a
    /// known-good backend, or decoded from policy).
    pub fn from_pcr_values(values: &[PcrValue]) -> Self {
        let bank = values.first().map(|v| v.bank.clone()).unwrap_or_default();
        let pcrs = values.iter().map(|v| (v.index, v.digest.clone())).collect();
        ReferenceMeasurements { bank, pcrs }
    }

    pub fn is_empty(&self) -> bool {
        self.pcrs.is_empty()
    }

    pub fn expected(&self, index: u32) -> Option<&[u8]> {
        self.pcrs.get(&index).map(|d| d.as_slice())
    }
}

/// Wraps a node's TPM backend with a long-lived attestation key, producing
/// and verifying nonce-bound quotes.
pub struct Attestor {
    backend: std::sync::Arc<dyn TpmBackend>,
    ak: KeyHandle,
}

impl Attestor {
    /// Create an attestor over `backend`, minting one AK up front. The PCR
    /// bank/selection are dictated per-challenge by the verifier, so they
    /// are not fixed here.
    pub fn new(backend: Box<dyn TpmBackend>) -> anyhow::Result<Self> {
        let ak = backend.create_ak(Algorithm::EccP256)?;
        // Store as Arc so the same TPM device can also back a TLS identity
        // (E2) — opening a second backend would be a *different* TPM.
        Ok(Attestor {
            backend: std::sync::Arc::from(backend),
            ak,
        })
    }

    /// Borrow the backend (e.g. to extend a PCR in tests, simulating a
    /// measured-state change / tamper).
    pub fn backend(&self) -> &dyn TpmBackend {
        self.backend.as_ref()
    }

    /// A shared handle to the *same* TPM backend — so an agent can mint a
    /// TLS identity (E2) on the same device that produces quotes.
    pub fn backend_arc(&self) -> std::sync::Arc<dyn TpmBackend> {
        self.backend.clone()
    }

    /// The public identifier of this attestor's AK — the bytes that appear as
    /// `quote.ak_public`. An endorser signs an [`Endorsement`] over this.
    pub fn ak_public(&self) -> Vec<u8> {
        self.ak.id.clone()
    }

    /// Capture this node's *current* measured state as a reference (e.g. to
    /// publish a known-good golden from a trusted node, or as a node's own
    /// expected baseline).
    pub fn reference_over(
        &self,
        bank: &str,
        indices: &[u32],
    ) -> anyhow::Result<ReferenceMeasurements> {
        let values = self.backend.pcr_read(bank, indices)?;
        Ok(ReferenceMeasurements::from_pcr_values(&values))
    }

    /// Produce evidence answering `challenge`: a fresh quote over the
    /// requested PCRs, bound to the challenge nonce (design §8.2).
    pub fn produce(
        &self,
        challenge: &AttestationChallenge,
        loaded_policy_revision: u64,
        agent_measurement: Option<String>,
        endorsement: Option<Endorsement>,
        tick: u64,
    ) -> anyhow::Result<AttestationEvidence> {
        let quote = self.backend.quote(
            &self.ak,
            &challenge.nonce,
            &challenge.pcr_bank,
            &challenge.pcr_selection,
        )?;
        Ok(AttestationEvidence {
            subject: challenge.subject,
            challenge_nonce: challenge.nonce.clone(),
            quote,
            agent_measurement,
            loaded_policy_revision,
            timestamp_tick: tick,
            endorsement,
            // Attach the measured-boot event log so a verifier can replay it
            // against the quote (event-log-attestation.md).
            event_log: self.backend.read_event_log().unwrap_or(None),
            // The IMA runtime log is staged by the node (read from the OS), not
            // the TPM backend — the node attaches it after `produce` (C1).
            ima_log: None,
        })
    }

    /// Verify a subject's `evidence` against `challenge`, appraising its quoted
    /// PCRs against the `accepted` reference sources (the policy golden, now
    /// multi-valued) rather than this node's own state. `match_policy` and
    /// `retired_action` tune the appraisal. Produces a signable
    /// [`AttestationResult`] with explanatory reason codes (design §8.4,
    /// `measured-state-transitions.md`).
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        challenge: &AttestationChallenge,
        evidence: &AttestationEvidence,
        accepted: &AcceptedReferences,
        anchors: &TrustAnchors,
        me: NodeId,
        tick: u64,
        match_policy: ReferenceMatchPolicy,
        retired_action: RetiredAction,
    ) -> AttestationResult {
        let mut reasons = Vec::new();

        // Endorsement: with trust anchors configured, the quote's AK must
        // carry a valid endorsement from a trusted endorser binding it to
        // this subject — otherwise the AK is untrusted (design §8.4).
        if !anchors.is_empty() {
            let endorsed = match &evidence.endorsement {
                Some(e) => {
                    e.verify_signature()
                        && e.binds(challenge.subject, &evidence.quote.ak_public)
                        // The endorser must be anchored directly, or its EK
                        // certificate chain must reach an anchored root.
                        && e.endorser_chains_to_anchor(|k| anchors.trusts(k))
                }
                None => false,
            };
            if !endorsed {
                reasons.push(ReasonCode::AkUntrusted);
            }
        }

        // The evidence must answer *this* challenge for *this* subject.
        if evidence.subject != challenge.subject {
            reasons.push(ReasonCode::EvidenceIncomplete);
        }
        if evidence.challenge_nonce != challenge.nonce {
            reasons.push(ReasonCode::NonceMismatch);
        }

        // 1) Signature + nonce: is this a genuine, fresh quote under its AK?
        //    (We use only these fields; PCR comparison is done against the
        //    reference below, not against the verifier's own state.)
        match self.backend.verify_quote(
            &evidence.quote,
            &evidence.quote.ak_public,
            &challenge.nonce,
        ) {
            Ok(v) => {
                if !v.signature_valid {
                    reasons.push(ReasonCode::QuoteSignatureInvalid);
                }
                if !v.nonce_matches && !reasons.contains(&ReasonCode::NonceMismatch) {
                    reasons.push(ReasonCode::NonceMismatch);
                }
            }
            Err(_) => reasons.push(ReasonCode::EvidenceIncomplete),
        }

        // 2) Measured state: appraise the quoted PCRs against the accepted
        //    reference sources (multi-valued, with validity windows). The
        //    `policy_revision` the challenge carries is the "now" on the
        //    revision clock; `tick` is the wall/logical clock.
        let mut reference_incomplete = false;
        let mut state_hard_fail = false;
        match accepted.appraise(
            &evidence.quote.pcr_values,
            tick,
            challenge.policy_revision,
            match_policy,
            retired_action,
        ) {
            ReferenceOutcome::Accepted => {}
            ReferenceOutcome::Unknown => {
                reasons.push(ReasonCode::ReferenceUnknown);
                state_hard_fail = true;
            }
            ReferenceOutcome::Retired { fail } => {
                reasons.push(ReasonCode::ReferenceRetired);
                state_hard_fail = fail;
            }
            ReferenceOutcome::Denied => {
                reasons.push(ReasonCode::ReferenceDenied);
                state_hard_fail = true;
            }
            ReferenceOutcome::Incomplete => reference_incomplete = true,
        }

        // Event log: a Semantic-class PCR must be backed by an event log that
        // (1) replays to the quote — integrity (Phase A) — and (2) whose
        // content satisfies fleet semantic policy — cmdline + per-event-digest
        // artifact (Phase C).
        let semantic: std::collections::BTreeSet<u32> = evidence
            .quote
            .pcr_values
            .iter()
            .filter(|pv| accepted.class_of(pv.index) == PcrClass::Semantic)
            .map(|pv| pv.index)
            .collect();
        if !semantic.is_empty() {
            match &evidence.event_log {
                None => reasons.push(ReasonCode::EventLogMissing),
                Some(bytes) => match tpm_core::eventlog::BootEventLog::from_bytes(bytes) {
                    Ok(log) if log.explains(&evidence.quote.pcr_values) => {
                        // Integrity holds → content-validate the semantic PCRs.
                        if accepted.appraise_eventlog(&log, &challenge.pcr_bank, &semantic)
                            == ReferenceOutcome::Denied
                        {
                            reasons.push(ReasonCode::ReferenceDenied);
                            state_hard_fail = true;
                        }
                    }
                    _ => reasons.push(ReasonCode::EventLogInconsistent),
                },
            }
        }

        // A stale policy revision is a soft (Warn) signal, not a failure.
        if evidence.loaded_policy_revision < challenge.policy_revision {
            reasons.push(ReasonCode::PolicyRevisionStale);
        }

        let hard_fail = state_hard_fail
            || reasons.iter().any(|r| {
                matches!(
                    r,
                    ReasonCode::QuoteSignatureInvalid
                        | ReasonCode::NonceMismatch
                        | ReasonCode::AkUntrusted
                        | ReasonCode::EvidenceIncomplete
                        | ReasonCode::EventLogMissing
                        | ReasonCode::EventLogInconsistent
                )
            });

        let (result, confidence) = if hard_fail {
            (Verdict::Fail, 0.0)
        } else if reference_incomplete {
            // No (or partial) reference to judge against: we can't assert
            // good, so withhold a Pass.
            if !reasons.contains(&ReasonCode::EvidenceIncomplete) {
                reasons.push(ReasonCode::EvidenceIncomplete);
            }
            (Verdict::Inconclusive, 0.0)
        } else if reasons.is_empty() {
            (Verdict::Pass, 1.0)
        } else {
            (Verdict::Warn, 0.5)
        };

        AttestationResult {
            subject: challenge.subject,
            verifier: me,
            result,
            reason_codes: reasons,
            policy_revision: challenge.policy_revision,
            confidence,
            timestamp_tick: tick,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm_core::backend::MockBackend;

    fn nid(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn challenge(subject: NodeId, policy_rev: u64) -> AttestationChallenge {
        AttestationChallenge {
            challenger: nid(99),
            subject,
            nonce: vec![1, 2, 3, 4],
            pcr_bank: "sha256".into(),
            pcr_selection: vec![0, 7],
            policy_revision: policy_rev,
            expires_at_tick: 100,
        }
    }

    /// The golden reference for a healthy node over the challenge's PCRs, as a
    /// single-valued accepted set (the bootstrap path).
    fn golden(attester: &Attestor) -> AcceptedReferences {
        AcceptedReferences::from_reference(attester.reference_over("sha256", &[0, 7]).unwrap())
    }

    #[test]
    fn healthy_node_passes_against_reference() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, None, 1).unwrap();
        let res = verifier.verify(
            &ch,
            &ev,
            &reference,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Pass, "reasons: {:?}", res.reason_codes);
    }

    #[test]
    fn divergence_from_reference_fails_with_reference_unknown() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        // Capture the golden BEFORE divergence.
        let reference = golden(&attester);

        // The attester's measured state now diverges from the golden — it
        // matches no accepted source.
        attester
            .backend()
            .pcr_extend("sha256", 0, &[0xAA; 32])
            .unwrap();

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, None, 1).unwrap();
        let res = verifier.verify(
            &ch,
            &ev,
            &reference,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::ReferenceUnknown));
    }

    #[test]
    fn missing_reference_is_inconclusive() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, None, 1).unwrap();
        // No accepted sources to compare against → cannot assert good.
        let res = verifier.verify(
            &ch,
            &ev,
            &AcceptedReferences::new("sha256"),
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Inconclusive);
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);

        let ch = challenge(nid(1), 5);
        let mut ev = attester.produce(&ch, 5, None, None, 1).unwrap();
        // Evidence carries a different nonce than the challenge wanted.
        ev.challenge_nonce = vec![9, 9, 9];
        let res = verifier.verify(
            &ch,
            &ev,
            &reference,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::NonceMismatch));
    }

    #[test]
    fn stale_policy_is_a_warn_not_a_fail() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);

        let ch = challenge(nid(1), 10);
        // Attester is on an older policy revision than the challenge wants.
        let ev = attester.produce(&ch, 8, None, None, 1).unwrap();
        let res = verifier.verify(
            &ch,
            &ev,
            &reference,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Warn);
        assert!(res.reason_codes.contains(&ReasonCode::PolicyRevisionStale));
    }

    use crate::crypto::MeshKeypair;

    #[test]
    fn endorsed_ak_passes_and_unendorsed_is_ak_untrusted() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);
        let endorser = MeshKeypair::from_seed([200u8; 32]);
        let anchors = TrustAnchors::with(endorser.public());
        let ch = challenge(nid(1), 5);

        // Endorsed (over the attester's actual AK) → trusted.
        let endorsement = Endorsement::issue(&endorser, nid(1), attester.ak_public());
        let ev = attester
            .produce(&ch, 5, None, Some(endorsement), 1)
            .unwrap();
        assert_eq!(
            verifier
                .verify(
                    &ch,
                    &ev,
                    &reference,
                    &anchors,
                    nid(2),
                    2,
                    ReferenceMatchPolicy::Flexible,
                    RetiredAction::Fail
                )
                .result,
            Verdict::Pass
        );

        // Unendorsed against an anchored verifier → AK_UNTRUSTED / Fail.
        let bare = attester.produce(&ch, 5, None, None, 1).unwrap();
        let res = verifier.verify(
            &ch,
            &bare,
            &reference,
            &anchors,
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::AkUntrusted));
    }

    #[test]
    fn endorsement_from_an_untrusted_endorser_fails() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);
        let trusted = MeshKeypair::from_seed([200u8; 32]);
        let rogue = MeshKeypair::from_seed([201u8; 32]);
        let anchors = TrustAnchors::with(trusted.public());
        let ch = challenge(nid(1), 5);

        let endorsement = Endorsement::issue(&rogue, nid(1), attester.ak_public());
        let ev = attester
            .produce(&ch, 5, None, Some(endorsement), 1)
            .unwrap();
        let res = verifier.verify(
            &ch,
            &ev,
            &reference,
            &anchors,
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::AkUntrusted));
    }

    #[test]
    fn endorsement_for_the_wrong_ak_fails() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);
        let endorser = MeshKeypair::from_seed([200u8; 32]);
        let anchors = TrustAnchors::with(endorser.public());
        let ch = challenge(nid(1), 5);

        // A validly-signed endorsement, but for a different AK.
        let endorsement = Endorsement::issue(&endorser, nid(1), vec![9, 9, 9, 9]);
        assert!(endorsement.verify_signature());
        let ev = attester
            .produce(&ch, 5, None, Some(endorsement), 1)
            .unwrap();
        let res = verifier.verify(
            &ch,
            &ev,
            &reference,
            &anchors,
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::AkUntrusted));
    }

    #[test]
    fn semantic_index_requires_a_consistent_event_log() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let mut accepted = golden(&attester);
        // PCR 0 is semantic → its quote must be backed by a replayable log.
        accepted.set_pcr_class(0, PcrClass::Semantic);
        let ch = challenge(nid(1), 5);

        // The mock attaches a log that replays to its quote → integrity holds.
        let ev = attester.produce(&ch, 5, None, None, 1).unwrap();
        assert!(ev.event_log.is_some(), "mock backend supplies an event log");
        let res = verifier.verify(
            &ch,
            &ev,
            &accepted,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Pass, "reasons {:?}", res.reason_codes);

        // No log when a semantic index is present → EVENT_LOG_MISSING / Fail.
        let mut no_log = ev.clone();
        no_log.event_log = None;
        let res = verifier.verify(
            &ch,
            &no_log,
            &accepted,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::EventLogMissing));

        // A log that does not replay to the quote → EVENT_LOG_INCONSISTENT / Fail.
        let mut bad = ev.clone();
        bad.event_log = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let res = verifier.verify(
            &ch,
            &bad,
            &accepted,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::EventLogInconsistent));
    }

    #[test]
    fn strict_only_quote_needs_no_event_log() {
        // Default (all-Strict) appraisal does not require a log — unchanged.
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let accepted = golden(&attester);
        let ch = challenge(nid(1), 5);
        let mut ev = attester.produce(&ch, 5, None, None, 1).unwrap();
        ev.event_log = None; // no log at all
        let res = verifier.verify(
            &ch,
            &ev,
            &accepted,
            &TrustAnchors::new(),
            nid(2),
            2,
            ReferenceMatchPolicy::Flexible,
            RetiredAction::Fail,
        );
        assert_eq!(res.result, Verdict::Pass, "reasons {:?}", res.reason_codes);
    }

    #[test]
    fn no_anchors_means_endorsement_not_required() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);
        let ch = challenge(nid(1), 5);
        // Empty anchors → a bare (unendorsed) quote still passes.
        let bare = attester.produce(&ch, 5, None, None, 1).unwrap();
        assert_eq!(
            verifier
                .verify(
                    &ch,
                    &bare,
                    &reference,
                    &TrustAnchors::new(),
                    nid(2),
                    2,
                    ReferenceMatchPolicy::Flexible,
                    RetiredAction::Fail
                )
                .result,
            Verdict::Pass
        );
    }
}
