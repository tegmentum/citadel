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
    /// The attester's evidence in response to a challenge (boxed: it carries
    /// the quote + endorsement and dwarfs the SWIM control variants).
    AttestEvidence(Box<AttestationEvidence>),
    /// A verifier's verdict over received evidence (gossiped).
    AttestResult(AttestationResult),
    /// A node advertises one of its log windows' LtHash digests (design
    /// log-shipping §11), so replicas can detect divergence.
    LogDigest(crate::logship::DigestAdvertisement),
    /// A replica asks the advertiser for its LtHash root over `[lo, hi)`, to
    /// binary-search the divergent sub-range.
    LogRangeQuery { boot_id: u64, lo: u64, hi: u64 },
    /// The advertiser's LtHash root over a queried sub-range.
    LogRangeRoot { boot_id: u64, lo: u64, hi: u64, root: Vec<u8> },
    /// A replica requests the advertiser's own-log records in `[lo, hi)` (a
    /// leaf of the binary search).
    LogPull { boot_id: u64, lo: u64, hi: u64 },
    /// The advertiser returns its records to a replica.
    LogRecords(Vec<crate::logship::EventRecord>),
    /// Origin → holder: store this erasure-coded shard of a sealed log window
    /// (bounded-fan-out durable evidence; design §12.4). Boxed: it carries a
    /// shard payload.
    LogFragmentStore(Box<crate::logship::LogFragment>),
    /// Holder → origin: a signed acknowledgement that a shard is stored, so
    /// the origin can track the window's durability.
    LogFragmentAck(Box<crate::evidence::EvidenceReceipt>),
    /// Recoverer → holder: please return your stored shard(s) for `record_id`.
    LogFragmentRequest { record_id: [u8; 32] },
    /// Holder → recoverer: a stored shard, returned for reconstruction. Boxed
    /// for the same reason as [`Self::LogFragmentStore`].
    LogFragmentReply(Box<crate::logship::LogFragment>),
    /// Origin → holder: this shard's placement has been superseded (the window
    /// migrated to a new policy and re-shipped elsewhere); drop it. Sent only
    /// after the new placement is durable, so evidence never dips below the
    /// reconstruction threshold during migration.
    LogFragmentDrop { record_id: [u8; 32] },
    /// A signed authorization to adopt new accepted measured states (design
    /// `measured-state-transitions.md` §10.2). Gossiped so every verifier that
    /// trusts the issuer converges on the same accepted set. Boxed: it carries
    /// reference entries/profiles and a certificate chain.
    ReferenceManifest(Box<crate::reference::ReferenceManifest>),
    /// Anti-entropy: the set of reference-manifest content ids a node holds, so
    /// a peer that missed a gossiped manifest can detect the gap and pull it.
    ReferenceDigest { ids: Vec<[u8; 32]> },
    /// A peer requests a reference manifest it is missing, by content id.
    ReferenceManifestRequest { id: [u8; 32] },
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
    /// Endorsement chaining the quote's AK to a trust root (design §8.2
    /// `ak_certificate_or_chain`). `None` when unendorsed — a verifier with
    /// trust anchors then flags `AK_UNTRUSTED`.
    #[serde(default)]
    pub endorsement: Option<Endorsement>,
}

/// An endorsement binding a node's attestation key to a trust root: an
/// **endorser** (a hardware EK / manufacturer / operator authority) signs
/// `(subject, ak_public)`. A verifier accepts a quote only if its AK carries
/// an endorsement from an endorser in its trust-anchor set — closing the
/// `AK_UNTRUSTED` gap where the AK is otherwise taken from the quote itself.
///
/// For the vTPM this maps onto `tpm_core::vtpm_credential` (a hardware TPM
/// signing a vTPM identity statement); binding the *per-quote AK* into that
/// hardware-signed statement is the remaining hardware step.
///
/// The optional `chain` lets the endorser itself be certified by a higher
/// authority (an EK certified by a manufacturer/CA root): a verifier can then
/// anchor the **root** instead of every individual endorser (design §3 EK
/// chain). With no chain, the endorser must be anchored directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endorsement {
    pub subject: NodeId,
    pub ak_public: Vec<u8>,
    pub endorser: MeshPublicKey,
    pub signature: Signature,
    /// Certificates from the endorser upward toward a trust root (the EK
    /// certificate chain). Empty when the endorser is anchored directly.
    #[serde(default)]
    pub chain: Vec<EndorserCert>,
}

impl Endorsement {
    fn signing_bytes(subject: &NodeId, ak_public: &[u8], endorser: &MeshPublicKey) -> Vec<u8> {
        serde_json::to_vec(&("ak-endorsement", subject, ak_public, endorser))
            .expect("serializable")
    }

    /// As an endorser, sign an endorsement of `subject`'s `ak_public`.
    pub fn issue(endorser_kp: &MeshKeypair, subject: NodeId, ak_public: Vec<u8>) -> Self {
        Self::issue_chained(endorser_kp, subject, ak_public, Vec::new())
    }

    /// Issue an endorsement that carries the endorser's certificate `chain`
    /// up toward a trust root.
    pub fn issue_chained(
        endorser_kp: &MeshKeypair,
        subject: NodeId,
        ak_public: Vec<u8>,
        chain: Vec<EndorserCert>,
    ) -> Self {
        let endorser = endorser_kp.public();
        let signature = endorser_kp.sign(&Self::signing_bytes(&subject, &ak_public, &endorser));
        Endorsement {
            subject,
            ak_public,
            endorser,
            signature,
            chain,
        }
    }

    /// Whether the endorser's signature over `(subject, ak_public)` is valid.
    pub fn verify_signature(&self) -> bool {
        self.endorser.verify(
            &Self::signing_bytes(&self.subject, &self.ak_public, &self.endorser),
            &self.signature,
        )
    }

    /// Whether this endorsement is for exactly `subject` and `ak_public`.
    pub fn binds(&self, subject: NodeId, ak_public: &[u8]) -> bool {
        self.subject == subject && self.ak_public == ak_public
    }

    /// Whether the endorser is trusted under `is_anchored`: either anchored
    /// directly, or its [`chain`](Self::chain) links (each cert valid and
    /// connecting) up to an anchored issuer (an EK→…→root chain).
    pub fn endorser_chains_to_anchor(&self, is_anchored: impl Fn(&MeshPublicKey) -> bool) -> bool {
        if is_anchored(&self.endorser) {
            return true;
        }
        let mut current = self.endorser;
        for cert in &self.chain {
            if cert.endorser != current || !cert.verify() {
                return false;
            }
            if is_anchored(&cert.issuer) {
                return true;
            }
            current = cert.issuer;
        }
        false
    }
}

/// A certificate binding an endorser's public key to an issuing authority —
/// one link of an EK certificate chain. The `issuer` signs the `endorser`
/// key; a verifier follows such links from a leaf endorser up to a root it
/// anchors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndorserCert {
    pub endorser: MeshPublicKey,
    pub issuer: MeshPublicKey,
    pub signature: Signature,
}

impl EndorserCert {
    fn signing_bytes(endorser: &MeshPublicKey, issuer: &MeshPublicKey) -> Vec<u8> {
        serde_json::to_vec(&("endorser-cert", endorser, issuer)).expect("serializable")
    }

    /// As `issuer`, certify `endorser`'s key.
    pub fn issue(issuer_kp: &MeshKeypair, endorser: MeshPublicKey) -> Self {
        let issuer = issuer_kp.public();
        let signature = issuer_kp.sign(&Self::signing_bytes(&endorser, &issuer));
        EndorserCert {
            endorser,
            issuer,
            signature,
        }
    }

    /// Whether the issuer's signature over the endorser key is valid.
    pub fn verify(&self) -> bool {
        self.issuer
            .verify(&Self::signing_bytes(&self.endorser, &self.issuer), &self.signature)
    }
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
    /// Quoted state matches no accepted reference source — likely tamper or an
    /// unauthorized state (design `measured-state-transitions.md`).
    ReferenceUnknown,
    /// Quoted state matches only a *retired* reference source — a node on a
    /// previously-good but withdrawn (unpatched) state.
    ReferenceRetired,
    /// Quoted state matches a known reference whose artifact fleet policy now
    /// forbids — revoked / denylisted / below baseline / wrong channel.
    ReferenceDenied,
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
