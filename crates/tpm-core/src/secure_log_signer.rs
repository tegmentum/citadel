//! TPM-backed [`CheckpointSigner`] for the secure log.
//!
//! Adapts a [`TpmBackend`] plus the citadel identity store to the
//! [`CheckpointSigner`] interface that the extracted `secure-log`
//! crate uses for Phase 3 checkpoint signing.
//!
//! Identity resolution mirrors what `NativeSecureLog::sign_segment`
//! used to do inline:
//!
//! 1. `sign_checkpoint(identity_name, msg)` looks up the named
//!    identity, finds its key object, extracts the handle blob, and
//!    asks the TPM backend to sign. The returned signer-identity
//!    string is the identity's UUID, which is what gets persisted in
//!    `secure_log_segments.signer_identity`.
//! 2. `verify_checkpoint(signer_identity, msg, sig)` parses the
//!    stored UUID, finds the identity by id, resolves its key the
//!    same way, and asks the backend to verify.

use secure_log::{CheckpointSigner, SignerError};

use crate::backend::{KeyHandle, TpmBackend};
use crate::store::Store;

/// A [`CheckpointSigner`] implementation that signs via a
/// [`TpmBackend`] and resolves identities through the citadel
/// [`Store`].
///
/// Borrowed references rather than `Arc`s keep this lightweight for
/// per-command CLI usage; for long-lived service use, hold the
/// backend / store as fields with an appropriate lifetime.
pub struct TpmCheckpointSigner<'a> {
    backend: &'a dyn TpmBackend,
    store: &'a Store,
    /// Optional measured-state gate: when set, the signer refuses to
    /// sign unless the live PCRs match the expected PolicyPCR digest.
    /// This binds the anchoring key to a known-good measured state so a
    /// tampered/unmeasured host cannot produce valid checkpoints.
    pcr_guard: Option<PcrGuard>,
    /// Optional anti-rollback: when set to an NV counter index, each
    /// checkpoint is signed over `H("artr" ‖ ckpt_hash ‖ counter)` with a
    /// freshly-incremented monotonic counter, and the counter is recorded
    /// (by checkpoint hash) so verification can reconstruct the message
    /// and a stale (rolled-back) checkpoint can be detected against the
    /// live counter.
    anti_rollback: Option<u32>,
}

/// A measured-state precondition for checkpoint signing: the live
/// `bank`/`indices` PCRs must hash to `expected_digest` (a PolicyPCR
/// digest, typically derived from a saved baseline).
#[derive(Clone)]
pub struct PcrGuard {
    pub bank: String,
    pub indices: Vec<u32>,
    pub expected_digest: Vec<u8>,
}

impl<'a> TpmCheckpointSigner<'a> {
    /// Build a new signer over the given backend and store.
    pub fn new(backend: &'a dyn TpmBackend, store: &'a Store) -> Self {
        Self {
            backend,
            store,
            pcr_guard: None,
            anti_rollback: None,
        }
    }

    /// Require the live PCRs to match `guard` before any signing.
    pub fn with_pcr_guard(mut self, guard: PcrGuard) -> Self {
        self.pcr_guard = Some(guard);
        self
    }

    /// Bind a monotonic NV counter (at `nv_index`) into every signed
    /// checkpoint for rollback detection.
    pub fn with_anti_rollback(mut self, nv_index: u32) -> Self {
        self.anti_rollback = Some(nv_index);
        self
    }

    /// Enforce the measured-state gate, if configured.
    fn check_pcr_guard(&self) -> Result<(), SignerError> {
        let Some(guard) = &self.pcr_guard else {
            return Ok(());
        };
        let current = self
            .backend
            .pcr_policy_digest(&guard.bank, &guard.indices)
            .map_err(|e| SignerError::SignFailed(e.to_string()))?;
        if current != guard.expected_digest {
            return Err(SignerError::SignFailed(format!(
                "measured-state gate failed: {} PCR {:?} differ from the expected baseline; \
                 refusing to sign checkpoint",
                guard.bank, guard.indices
            )));
        }
        Ok(())
    }

    /// If the identity's key object records a PCR-policy binding (stored
    /// at creation under `metadata.pcr_policy`), return `(bank, indices)`.
    fn pcr_binding_for_identity(
        &self,
        identity_name: &str,
    ) -> Result<Option<(String, Vec<u32>)>, SignerError> {
        let identity = self
            .store
            .get_identity(identity_name)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| SignerError::UnknownIdentity(identity_name.to_string()))?;
        let key = self
            .store
            .get_object_by_id(&identity.key_object_id)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| SignerError::Storage("identity references missing key".into()))?;
        let Some(p) = key.metadata.get("pcr_policy") else {
            return Ok(None);
        };
        let bank = p
            .get("bank")
            .and_then(|b| b.as_str())
            .ok_or_else(|| SignerError::Storage("malformed pcr_policy binding".into()))?
            .to_string();
        let indices = p
            .get("indices")
            .and_then(|i| i.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect())
            .unwrap_or_default();
        Ok(Some((bank, indices)))
    }

    fn handle_for_identity(&self, identity_name: &str) -> Result<KeyHandle, SignerError> {
        let identity = self
            .store
            .get_identity(identity_name)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| SignerError::UnknownIdentity(identity_name.to_string()))?;
        let key = self
            .store
            .get_object_by_id(&identity.key_object_id)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| {
                SignerError::Storage(format!(
                    "identity '{}' references missing key {}",
                    identity_name, identity.key_object_id
                ))
            })?;
        let handle_blob = key.handle_blob.clone().ok_or_else(|| {
            SignerError::Storage(format!(
                "key '{}' has no handle blob (was it imported from a manifest?)",
                key.path
            ))
        })?;
        Ok(KeyHandle {
            id: handle_blob,
            path: key.path.to_string(),
        })
    }

    fn handle_for_signer_id(&self, signer_identity: &str) -> Result<KeyHandle, SignerError> {
        let ident_uuid: uuid::Uuid = signer_identity.parse().map_err(|_| {
            SignerError::Storage(format!(
                "signer_identity '{}' is not a valid UUID",
                signer_identity
            ))
        })?;
        let all_ids = self
            .store
            .list_identities()
            .map_err(|e| SignerError::Storage(e.to_string()))?;
        let identity = all_ids
            .into_iter()
            .find(|i| i.id == ident_uuid)
            .ok_or_else(|| {
                SignerError::UnknownIdentity(format!(
                    "no identity with id {}",
                    signer_identity
                ))
            })?;
        let key = self
            .store
            .get_object_by_id(&identity.key_object_id)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| {
                SignerError::Storage(format!(
                    "identity {} references missing key",
                    identity.name
                ))
            })?;
        let handle_blob = key.handle_blob.clone().ok_or_else(|| {
            SignerError::Storage("signer key has no handle blob".into())
        })?;
        Ok(KeyHandle {
            id: handle_blob,
            path: key.path.to_string(),
        })
    }
}

impl<'a> CheckpointSigner for TpmCheckpointSigner<'a> {
    fn sign_checkpoint(
        &self,
        identity_name: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, String), SignerError> {
        // Refuse to sign unless the host is in the expected measured
        // state (if a guard is configured).
        self.check_pcr_guard()?;
        // Look up identity now so we have both the handle (for the
        // backend) and the UUID (for the persisted signer_identity).
        let identity = self
            .store
            .get_identity(identity_name)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| SignerError::UnknownIdentity(identity_name.to_string()))?;
        let handle = self.handle_for_identity(identity_name)?;

        // Anti-rollback: advance the monotonic counter and bind it into
        // the message actually signed, then record it by checkpoint hash.
        let (signed_message, counter) = match self.anti_rollback {
            Some(idx) => {
                let c = self
                    .backend
                    .nv_increment(idx)
                    .map_err(|e| SignerError::SignFailed(e.to_string()))?;
                (bind_counter(message, c), Some(c))
            }
            None => (message.to_vec(), None),
        };

        // If the identity's key is bound to a PCR policy (created with
        // `--pcr-bind`), sign under a policy session so the TPM itself
        // enforces the measured state; otherwise sign with the password.
        let signature = match self.pcr_binding_for_identity(identity_name)? {
            Some((bank, indices)) => self
                .backend
                .sign_with_policy(&handle, &signed_message, &bank, &indices)
                .map_err(|e| SignerError::SignFailed(e.to_string()))?,
            None => self
                .backend
                .sign(&handle, &signed_message)
                .map_err(|e| SignerError::SignFailed(e.to_string()))?,
        };

        if let Some(c) = counter {
            self.store
                .set_checkpoint_counter(&hex_str(message), c)
                .map_err(|e| SignerError::Storage(e.to_string()))?;
        }
        Ok((signature, identity.id.to_string()))
    }

    fn verify_checkpoint(
        &self,
        signer_identity: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignerError> {
        let handle = self.handle_for_signer_id(signer_identity)?;
        // Reconstruct the bound message if this checkpoint carries a
        // recorded anti-rollback counter; else verify the bare message.
        let signed_message = match self
            .store
            .get_checkpoint_counter(&hex_str(message))
            .map_err(|e| SignerError::Storage(e.to_string()))?
        {
            Some(c) => bind_counter(message, c),
            None => message.to_vec(),
        };
        self.backend
            .verify_signature(&handle, &signed_message, signature)
            .map_err(|e| SignerError::VerifyFailed(e.to_string()))
    }
}

/// Bind an anti-rollback counter into a checkpoint message:
/// `SHA-256("artr" ‖ message ‖ counter_be)`.
fn bind_counter(message: &[u8], counter: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + message.len() + 8);
    buf.extend_from_slice(b"artr");
    buf.extend_from_slice(message);
    buf.extend_from_slice(&counter.to_be_bytes());
    crate::backend::hash_for_bank("sha256", &buf).expect("sha256 is always available")
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use secure_log::CheckpointSigner;

    #[test]
    fn guard_blocks_signing_when_pcrs_diverge_from_baseline() {
        let store = Store::open_memory().unwrap();
        let backend = MockBackend::new();

        // Capture the current measured state as the expected baseline.
        let expected = backend.pcr_policy_digest("sha256", &[0, 7]).unwrap();
        let guard = PcrGuard {
            bank: "sha256".to_string(),
            indices: vec![0, 7],
            expected_digest: expected,
        };
        let signer = TpmCheckpointSigner::new(&backend, &store).with_pcr_guard(guard);

        // PCRs still match: the guard passes, so signing proceeds far
        // enough to fail on the (absent) identity rather than the gate.
        let err = signer
            .sign_checkpoint("no-such-identity", b"root")
            .expect_err("no identity exists yet");
        assert!(
            !err.to_string().contains("measured-state gate"),
            "guard should have passed while PCRs match: {err}"
        );

        // Extend a bound PCR: the live state now diverges from baseline.
        backend.pcr_extend("sha256", 0, &[0x99u8; 32]).unwrap();
        let err = signer
            .sign_checkpoint("no-such-identity", b"root")
            .expect_err("guard must block signing after the PCR changes");
        assert!(
            err.to_string().contains("measured-state gate failed"),
            "expected the measured-state gate to fail, got: {err}"
        );
    }

    #[test]
    fn no_guard_allows_signing_attempt_regardless_of_pcrs() {
        let store = Store::open_memory().unwrap();
        let backend = MockBackend::new();
        backend.pcr_extend("sha256", 0, &[0x99u8; 32]).unwrap();
        let signer = TpmCheckpointSigner::new(&backend, &store);
        // No guard => proceeds to identity lookup (fails there, not on a gate).
        let err = signer.sign_checkpoint("no-such-identity", b"root").unwrap_err();
        assert!(!err.to_string().contains("measured-state gate"));
    }
}
