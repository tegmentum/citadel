//! Operator write path (CP5). The control plane has **no key that decides
//! trust** — it relays operator-signed actions into the mesh as inputs nodes
//! evaluate, and keeps a tamper-evident audit of what it relayed.
//!
//! An [`OperatorAction`] is a registered operator's signature over `(kind,
//! target)` — e.g. authorizing the publication of a specific reference manifest
//! (`target` = the manifest's content id). The CP verifies the operator is
//! registered and the signature is valid before relaying; a single authorized
//! signature is required by default. **Severe actions may require quorum/co-sign
//! — model that by carrying multiple `OperatorAction`s and a per-kind threshold;
//! this v1 enforces single-sig.**

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};

/// A registered operator's signed authorization for one write action.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OperatorAction {
    pub operator: MeshPublicKey,
    /// The action kind (e.g. `"publish-policy"`).
    pub kind: String,
    /// What the action authorizes (e.g. a manifest content id).
    pub target: [u8; 32],
    pub signature: Signature,
}

impl OperatorAction {
    fn signing_bytes(kind: &str, target: &[u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&("operator-action", kind, target)).expect("serializable")
    }

    /// Sign an action as `operator` (client/test side).
    pub fn sign(operator: &MeshKeypair, kind: impl Into<String>, target: [u8; 32]) -> Self {
        let kind = kind.into();
        let signature = operator.sign(&Self::signing_bytes(&kind, &target));
        OperatorAction {
            operator: operator.public(),
            kind,
            target,
            signature,
        }
    }

    /// Verify the operator's signature over `(kind, target)`.
    pub fn verify(&self) -> bool {
        self.operator.verify(
            &Self::signing_bytes(&self.kind, &self.target),
            &self.signature,
        )
    }
}

/// One link in the control plane's operator-action audit chain — a
/// tamper-evident record of every write the CP relayed (the "record operator
/// decisions" duty, §5.3).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OperatorAuditEntry {
    pub seq: u64,
    pub kind: String,
    /// Hex of the action target (e.g. manifest content id).
    pub target: String,
    /// Hex of the operator's key fingerprint.
    pub operator: String,
    pub tick: u64,
    pub prev_hash: String,
    pub hash: String,
}

/// Compute the chain hash for an entry: `BLAKE3(seq ‖ kind ‖ target ‖ operator ‖
/// tick ‖ prev_hash)`.
pub(crate) fn entry_hash(
    seq: u64,
    kind: &str,
    target: &[u8; 32],
    operator: &[u8; 32],
    tick: u64,
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&seq.to_le_bytes());
    h.update(kind.as_bytes());
    h.update(target);
    h.update(operator);
    h.update(&tick.to_le_bytes());
    h.update(prev_hash);
    *h.finalize().as_bytes()
}

/// Why a write was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The signer is not a registered operator.
    Unauthorized,
    /// The operator signature didn't verify.
    BadSignature,
    /// The action authorizes a different target than the supplied artifact.
    TargetMismatch,
    /// The relayed artifact (e.g. manifest) isn't validly signed by its authority.
    BadArtifact,
}
