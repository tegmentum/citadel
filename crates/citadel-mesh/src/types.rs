//! Signed wire types: the gossip envelope, its messages, and the
//! attestation challenge/evidence/result records (design §8, §9.4).
//!
//! Every message that crosses the mesh is wrapped in a [`GossipEnvelope`]
//! and signed by the sender's mesh key over a canonical byte encoding. A
//! recipient verifies the signature *and* (in [`crate::node`]) that the
//! enclosed `sender_public_key` matches the key it already knows for that
//! node — so a forged sender or a tampered payload is rejected before it
//! can influence membership or trust.

use serde::{Deserialize, Serialize};

use tpm_core::backend::QuoteData;

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::id::{MeshId, NodeId};
use crate::membership::MemberUpdate;

/// A signed mesh message with piggybacked membership updates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipEnvelope {
    pub mesh_id: MeshId,
    pub sender: NodeId,
    /// The sender's mesh public key (bound into the signature). Lets a
    /// recipient verify even before learning the sender via membership;
    /// the node loop still checks it against the known key.
    pub sender_public_key: MeshPublicKey,
    pub sender_incarnation: u64,
    pub sequence: u64,
    pub message: GossipMessage,
    pub piggyback: Vec<MemberUpdate>,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl GossipEnvelope {
    /// Canonical bytes covered by the signature (everything but the
    /// signature itself), encoded as a positional JSON array so field
    /// ordering is fixed and map-key ordering can't vary.
    fn signing_payload(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            &self.mesh_id,
            &self.sender,
            &self.sender_public_key,
            self.sender_incarnation,
            self.sequence,
            &self.message,
            &self.piggyback,
            self.timestamp_tick,
        ))
        .expect("envelope fields are serializable")
    }

    /// Sign this envelope with the sender's keypair (consuming/returning).
    pub fn signed(mut self, kp: &MeshKeypair) -> Self {
        self.signature = kp.sign(&self.signing_payload());
        self
    }

    /// Verify the signature against the enclosed `sender_public_key`.
    pub fn verify_signature(&self) -> bool {
        self.sender_public_key.verify(&self.signing_payload(), &self.signature)
    }
}

/// The body of a gossip envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    /// SWIM direct probe.
    Ping,
    /// SWIM probe acknowledgement.
    Ack,
    /// SWIM indirect probe: "please ping `target` on my behalf".
    PingReq { target: NodeId },
    /// Indirect-probe result relayed back to the requester.
    PingReqAck { target: NodeId, alive: bool },
    /// A witness/peer challenges the recipient to attest.
    AttestChallenge(AttestationChallenge),
    /// The attester's evidence in response to a challenge.
    AttestEvidence(AttestationEvidence),
    /// A verifier's verdict over received evidence (gossiped).
    AttestResult(AttestationResult),
}

// -- Attestation records (design §8) --

/// A nonce-bound request to attest a selection of PCRs (design §8.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationChallenge {
    pub challenger: NodeId,
    pub subject: NodeId,
    pub nonce: Vec<u8>,
    pub pcr_bank: String,
    pub pcr_selection: Vec<u32>,
    pub policy_revision: u64,
    pub expires_at_tick: u64,
}

/// Minimum evidence bundle (design §8.2). The TPM quote is carried as the
/// existing [`QuoteData`] so the verifier path reuses `verify_quote`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub subject: NodeId,
    pub challenge_nonce: Vec<u8>,
    pub quote: QuoteData,
    pub agent_measurement: Option<String>,
    pub loaded_policy_revision: u64,
    pub timestamp_tick: u64,
}

/// A verifier's signed verdict over a subject's evidence (design §8.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationResult {
    pub subject: NodeId,
    pub verifier: NodeId,
    pub result: Verdict,
    pub reason_codes: Vec<ReasonCode>,
    pub policy_revision: u64,
    /// Verifier confidence in `[0,1]`.
    pub confidence: f32,
    pub timestamp_tick: u64,
}

/// Overall attestation verdict (design §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
    Inconclusive,
}

/// Machine-readable reasons for a verdict (design §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    PcrMismatch,
    QuoteSignatureInvalid,
    NonceMismatch,
    AkUntrusted,
    EventLogMissing,
    EventLogInconsistent,
    AgentVersionDeprecated,
    PolicyRevisionStale,
    RoleNotAuthorized,
    NetworkLocationUnexpected,
    ClockSkewExcessive,
    EvidenceIncomplete,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn envelope_sign_verify_and_tamper() {
        let kp = MeshKeypair::from_seed([9u8; 32]);
        let env = GossipEnvelope {
            mesh_id: MeshId::new("m"),
            sender: nid(1),
            sender_public_key: kp.public(),
            sender_incarnation: 0,
            sequence: 1,
            message: GossipMessage::Ping,
            piggyback: vec![],
            timestamp_tick: 5,
            signature: Signature::zero(),
        }
        .signed(&kp);

        assert!(env.verify_signature());

        // Tamper the sequence: signature no longer matches.
        let mut tampered = env.clone();
        tampered.sequence = 2;
        assert!(!tampered.verify_signature());
    }

    #[test]
    fn forged_sender_key_does_not_verify() {
        let kp = MeshKeypair::from_seed([1u8; 32]);
        let attacker = MeshKeypair::from_seed([2u8; 32]);
        // Attacker signs but claims the victim's public key.
        let mut env = GossipEnvelope {
            mesh_id: MeshId::new("m"),
            sender: nid(1),
            sender_public_key: kp.public(), // victim's key
            sender_incarnation: 0,
            sequence: 1,
            message: GossipMessage::Ping,
            piggyback: vec![],
            timestamp_tick: 0,
            signature: Signature::zero(),
        };
        env.signature = attacker.sign(&env.signing_payload());
        assert!(!env.verify_signature(), "victim key can't verify attacker's signature");
    }

    #[test]
    fn reason_code_serializes_screaming() {
        let j = serde_json::to_string(&ReasonCode::PcrMismatch).unwrap();
        assert_eq!(j, "\"PCR_MISMATCH\"");
    }
}
