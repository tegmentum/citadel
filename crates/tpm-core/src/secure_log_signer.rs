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
}

impl<'a> TpmCheckpointSigner<'a> {
    /// Build a new signer over the given backend and store.
    pub fn new(backend: &'a dyn TpmBackend, store: &'a Store) -> Self {
        Self { backend, store }
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
        // Look up identity now so we have both the handle (for the
        // backend) and the UUID (for the persisted signer_identity).
        let identity = self
            .store
            .get_identity(identity_name)
            .map_err(|e| SignerError::Storage(e.to_string()))?
            .ok_or_else(|| SignerError::UnknownIdentity(identity_name.to_string()))?;
        let handle = self.handle_for_identity(identity_name)?;
        let signature = self
            .backend
            .sign(&handle, message)
            .map_err(|e| SignerError::SignFailed(e.to_string()))?;
        Ok((signature, identity.id.to_string()))
    }

    fn verify_checkpoint(
        &self,
        signer_identity: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignerError> {
        let handle = self.handle_for_signer_id(signer_identity)?;
        self.backend
            .verify_signature(&handle, message, signature)
            .map_err(|e| SignerError::VerifyFailed(e.to_string()))
    }
}
