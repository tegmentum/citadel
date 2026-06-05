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

use std::collections::BTreeMap;

use tpm_core::backend::{KeyHandle, PcrValue, TpmBackend};
use tpm_core::model::Algorithm;

use crate::id::NodeId;
use crate::types::{
    AttestationChallenge, AttestationEvidence, AttestationResult, ReasonCode, Verdict,
};

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
    backend: Box<dyn TpmBackend>,
    ak: KeyHandle,
}

impl Attestor {
    /// Create an attestor over `backend`, minting one AK up front. The PCR
    /// bank/selection are dictated per-challenge by the verifier, so they
    /// are not fixed here.
    pub fn new(backend: Box<dyn TpmBackend>) -> anyhow::Result<Self> {
        let ak = backend.create_ak(Algorithm::EccP256)?;
        Ok(Attestor { backend, ak })
    }

    /// Borrow the backend (e.g. to extend a PCR in tests, simulating a
    /// measured-state change / tamper).
    pub fn backend(&self) -> &dyn TpmBackend {
        self.backend.as_ref()
    }

    /// Capture this node's *current* measured state as a reference (e.g. to
    /// publish a known-good golden from a trusted node, or as a node's own
    /// expected baseline).
    pub fn reference_over(&self, bank: &str, indices: &[u32]) -> anyhow::Result<ReferenceMeasurements> {
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
        })
    }

    /// Verify a subject's `evidence` against `challenge`, matching its quoted
    /// PCRs against `reference` (the policy golden) rather than this node's
    /// own state. Produces a signable [`AttestationResult`] with explanatory
    /// reason codes (design §8.4).
    pub fn verify(
        &self,
        challenge: &AttestationChallenge,
        evidence: &AttestationEvidence,
        reference: &ReferenceMeasurements,
        me: NodeId,
        tick: u64,
    ) -> AttestationResult {
        let mut reasons = Vec::new();

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
        match self
            .backend
            .verify_quote(&evidence.quote, &evidence.quote.ak_public, &challenge.nonce)
        {
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

        // 2) Measured state: compare each quoted PCR to the reference golden.
        //    With no reference we cannot judge the state — Inconclusive.
        let mut reference_incomplete = false;
        if reference.is_empty() {
            reference_incomplete = true;
        } else {
            for quoted in &evidence.quote.pcr_values {
                match reference.expected(quoted.index) {
                    Some(expected) if expected == quoted.digest.as_slice() => {}
                    Some(_) => {
                        if !reasons.contains(&ReasonCode::PcrMismatch) {
                            reasons.push(ReasonCode::PcrMismatch);
                        }
                    }
                    None => reference_incomplete = true,
                }
            }
        }

        // A stale policy revision is a soft (Warn) signal, not a failure.
        if evidence.loaded_policy_revision < challenge.policy_revision {
            reasons.push(ReasonCode::PolicyRevisionStale);
        }

        let hard_fail = reasons.iter().any(|r| {
            matches!(
                r,
                ReasonCode::PcrMismatch
                    | ReasonCode::QuoteSignatureInvalid
                    | ReasonCode::NonceMismatch
                    | ReasonCode::AkUntrusted
                    | ReasonCode::EvidenceIncomplete
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

    /// The golden reference for a healthy node over the challenge's PCRs.
    fn golden(attester: &Attestor) -> ReferenceMeasurements {
        attester.reference_over("sha256", &[0, 7]).unwrap()
    }

    #[test]
    fn healthy_node_passes_against_reference() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, 1).unwrap();
        let res = verifier.verify(&ch, &ev, &reference, nid(2), 2);
        assert_eq!(res.result, Verdict::Pass, "reasons: {:?}", res.reason_codes);
    }

    #[test]
    fn divergence_from_reference_fails_with_pcr_mismatch() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        // Capture the golden BEFORE divergence.
        let reference = golden(&attester);

        // The attester's measured state now diverges from the golden.
        attester.backend().pcr_extend("sha256", 0, &[0xAA; 32]).unwrap();

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, 1).unwrap();
        let res = verifier.verify(&ch, &ev, &reference, nid(2), 2);
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::PcrMismatch));
    }

    #[test]
    fn missing_reference_is_inconclusive() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, 1).unwrap();
        // No golden to compare against → cannot assert good.
        let res = verifier.verify(&ch, &ev, &ReferenceMeasurements::default(), nid(2), 2);
        assert_eq!(res.result, Verdict::Inconclusive);
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let reference = golden(&attester);

        let ch = challenge(nid(1), 5);
        let mut ev = attester.produce(&ch, 5, None, 1).unwrap();
        // Evidence carries a different nonce than the challenge wanted.
        ev.challenge_nonce = vec![9, 9, 9];
        let res = verifier.verify(&ch, &ev, &reference, nid(2), 2);
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
        let ev = attester.produce(&ch, 8, None, 1).unwrap();
        let res = verifier.verify(&ch, &ev, &reference, nid(2), 2);
        assert_eq!(res.result, Verdict::Warn);
        assert!(res.reason_codes.contains(&ReasonCode::PolicyRevisionStale));
    }
}
