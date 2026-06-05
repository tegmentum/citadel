//! The attestation evidence path, over a [`tpm_core`] TPM backend.
//!
//! A node is both an **attester** (it quotes its own PCRs when challenged)
//! and a **verifier** (it checks peers' evidence against its own reference
//! state). [`Attestor`] wraps the node's TPM backend and provides both
//! directions, reusing `backend.quote` / `backend.verify_quote`.
//!
//! Phase 0 uses [`tpm_core::backend::MockBackend`], where a verifier
//! compares an attester's quoted PCRs against the verifier's *own* current
//! PCRs — so two healthy nodes (identical mock PCR state) agree, and a node
//! whose PCRs were extended (a stand-in for tamper) produces a quote that
//! every peer independently flags as `PCR_MISMATCH`. Phase 1 swaps in the
//! real vTPM backend behind the same seam.

use tpm_core::backend::{KeyHandle, TpmBackend};
use tpm_core::model::Algorithm;

use crate::id::NodeId;
use crate::types::{
    AttestationChallenge, AttestationEvidence, AttestationResult, ReasonCode, Verdict,
};

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

    /// Verify a subject's `evidence` against `challenge`, using this node's
    /// own backend as the reference measured state. Produces a signed-able
    /// [`AttestationResult`] with explanatory reason codes (design §8.4).
    pub fn verify(
        &self,
        challenge: &AttestationChallenge,
        evidence: &AttestationEvidence,
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
                if v.pcr_matches.iter().any(|m| !m.matches) {
                    reasons.push(ReasonCode::PcrMismatch);
                }
            }
            Err(_) => reasons.push(ReasonCode::EvidenceIncomplete),
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

    #[test]
    fn healthy_node_passes_peer_verification() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, 1).unwrap();
        let res = verifier.verify(&ch, &ev, nid(2), 2);
        assert_eq!(res.result, Verdict::Pass, "reasons: {:?}", res.reason_codes);
    }

    #[test]
    fn tampered_pcr_state_fails_with_pcr_mismatch() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();

        // The attester's measured state diverges from the verifier's
        // reference (a stand-in for compromise).
        attester.backend().pcr_extend("sha256", 0, &[0xAA; 32]).unwrap();

        let ch = challenge(nid(1), 5);
        let ev = attester.produce(&ch, 5, None, 1).unwrap();
        let res = verifier.verify(&ch, &ev, nid(2), 2);
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::PcrMismatch));
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();

        let ch = challenge(nid(1), 5);
        let mut ev = attester.produce(&ch, 5, None, 1).unwrap();
        // Evidence carries a different nonce than the challenge wanted.
        ev.challenge_nonce = vec![9, 9, 9];
        let res = verifier.verify(&ch, &ev, nid(2), 2);
        assert_eq!(res.result, Verdict::Fail);
        assert!(res.reason_codes.contains(&ReasonCode::NonceMismatch));
    }

    #[test]
    fn stale_policy_is_a_warn_not_a_fail() {
        let attester = Attestor::new(Box::new(MockBackend::new())).unwrap();
        let verifier = Attestor::new(Box::new(MockBackend::new())).unwrap();

        let ch = challenge(nid(1), 10);
        // Attester is on an older policy revision than the challenge wants.
        let ev = attester.produce(&ch, 8, None, 1).unwrap();
        let res = verifier.verify(&ch, &ev, nid(2), 2);
        assert_eq!(res.result, Verdict::Warn);
        assert!(res.reason_codes.contains(&ReasonCode::PolicyRevisionStale));
    }
}
