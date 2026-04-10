use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, ObjectPath};

/// Abstract interface to a TPM backend (real hardware, simulator, or mock).
pub trait TpmBackend: Send + Sync {
    fn status(&self) -> anyhow::Result<BackendStatus>;
    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle>;
    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Verify a previously-produced signature over `data` using the
    /// public component of `handle`.
    ///
    /// Default implementation uses symmetric re-sign comparison:
    /// re-run `sign` and check that the output matches. This is
    /// correct for deterministic signatures (like the `MockBackend`
    /// and TPM quotes with null scheme) but *not* for real
    /// ECDSA/RSA-PSS where the same input can produce many valid
    /// signatures. Hardware-backed implementations override this
    /// with a proper public-key verification call.
    ///
    /// The secure log checkpoint verifier uses this in place of
    /// re-signing so that swapping in a real backend gives real
    /// cryptographic verification automatically.
    fn verify_signature(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        let recomputed = self.sign(handle, data)?;
        Ok(recomputed == signature)
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>>;

    /// Seal data under a policy. Returns an opaque sealed blob.
    fn seal(&self, data: &[u8], policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData>;

    /// Unseal previously sealed data.
    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>>;

    /// Read PCR values for the given bank and indices.
    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>>;

    /// Define an NV index with the given size.
    fn nv_define(&self, index: u32, size: usize) -> anyhow::Result<()>;

    /// Write data to an NV index.
    fn nv_write(&self, index: u32, data: &[u8]) -> anyhow::Result<()>;

    /// Read data from an NV index.
    fn nv_read(&self, index: u32, size: usize) -> anyhow::Result<Vec<u8>>;

    /// Delete an NV index.
    fn nv_undefine(&self, index: u32) -> anyhow::Result<()>;

    /// Create an attestation key.
    fn create_ak(&self, algorithm: Algorithm) -> anyhow::Result<KeyHandle>;

    /// Generate a TPM quote: sign PCR values with an AK.
    fn quote(
        &self,
        ak_handle: &KeyHandle,
        nonce: &[u8],
        pcr_bank: &str,
        pcr_indices: &[u32],
    ) -> anyhow::Result<QuoteData>;

    /// Verify a TPM quote against expected PCR values.
    fn verify_quote(
        &self,
        quote: &QuoteData,
        ak_public: &[u8],
        nonce: &[u8],
    ) -> anyhow::Result<QuoteVerification>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub backend_type: String,
    pub manufacturer: String,
    pub firmware_version: String,
    pub available: bool,
}

#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub id: Vec<u8>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    pub blob: Vec<u8>,
    pub policy_digest: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub bank: String,
    pub index: u32,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteData {
    /// The signed attestation statement.
    pub attestation: Vec<u8>,
    /// The signature over the attestation.
    pub signature: Vec<u8>,
    /// PCR values included in the quote.
    pub pcr_values: Vec<PcrValue>,
    /// The nonce used in the quote.
    pub nonce: Vec<u8>,
    /// The AK public key material.
    pub ak_public: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerification {
    /// Whether the signature is valid.
    pub signature_valid: bool,
    /// Whether the nonce matches.
    pub nonce_matches: bool,
    /// Per-PCR comparison results.
    pub pcr_matches: Vec<PcrMatchResult>,
    /// Overall verification result.
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMatchResult {
    pub index: u32,
    pub bank: String,
    pub expected: String,
    pub actual: String,
    pub matches: bool,
}
