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

    /// Extend PCR `index` of `bank` with `digest`: `PCR = H(PCR ‖ digest)`.
    ///
    /// `digest` must be the bank's hash size (e.g. 32 bytes for sha256);
    /// it is the already-hashed measurement, matching TPM2_PCR_Extend
    /// semantics. Use [`hash_for_bank`] to derive a digest from raw bytes.
    fn pcr_extend(&self, bank: &str, index: u32, digest: &[u8]) -> anyhow::Result<()>;

    /// Compute the TPM2 `PolicyPCR` authorization digest binding the
    /// given PCRs at their *current* values. Sealing data under this
    /// digest gates unsealing on those PCRs being unchanged.
    ///
    /// The default reads current PCRs and computes the standard
    /// sha256 PolicyPCR digest:
    ///   `H( 0^32 ‖ TPM_CC_PolicyPCR ‖ pcrSelection ‖ H(concat PCR values) )`
    /// which is what a real TPM derives for a PolicyPCR session, so it
    /// is consistent whether the backend is mock, vTPM, or hardware.
    fn pcr_policy_digest(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<u8>> {
        let values = self.pcr_read(bank, indices)?;
        pcr_policy_digest_from(bank, &values)
    }

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

/// Digest size in bytes for a named PCR/hash bank.
pub fn bank_digest_size(bank: &str) -> anyhow::Result<usize> {
    match bank {
        "sha256" => Ok(32),
        "sha384" => Ok(48),
        "sha1" => Ok(20),
        other => anyhow::bail!("unsupported PCR bank: {other}"),
    }
}

/// Hash raw bytes to a digest in the given bank, for feeding into
/// [`TpmBackend::pcr_extend`] or as a Merkle-log measurement leaf.
///
/// Only `sha256` is implemented today (the default citadel bank);
/// `sha384`/`sha1` are recognized by [`bank_digest_size`] for read/quote
/// paths but cannot be produced here yet.
pub fn hash_for_bank(bank: &str, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    match bank {
        "sha256" => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(data);
            Ok(h.finalize().to_vec())
        }
        other => anyhow::bail!("hashing for bank '{other}' is not supported (use sha256)"),
    }
}

/// Compute the TPM2 `PolicyPCR` (sha256) authorization digest over an
/// explicit set of PCR values, rather than the live ones. Used to derive
/// the expected digest from a saved baseline so the live state can be
/// compared against it. The PCR selection is taken from each value's
/// `index`.
pub fn pcr_policy_digest_from(bank: &str, values: &[PcrValue]) -> anyhow::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
    let alg_id: u16 = match bank {
        "sha256" => 0x000B,
        "sha384" => 0x000C,
        "sha1" => 0x0004,
        other => anyhow::bail!("unsupported PCR bank: {other}"),
    };

    // pcrDigest = H(concat of PCR digests, ascending index)
    let mut sorted: Vec<&PcrValue> = values.iter().collect();
    sorted.sort_by_key(|v| v.index);
    let mut concat = Vec::new();
    for v in &sorted {
        concat.extend_from_slice(&v.digest);
    }
    let pcr_digest = {
        let mut h = Sha256::new();
        h.update(&concat);
        h.finalize().to_vec()
    };

    // TPML_PCR_SELECTION { count, [TPMS_PCR_SELECTION{ hash, size=3, bitmap }] }
    let mut sel = Vec::new();
    sel.extend_from_slice(&1u32.to_be_bytes());
    sel.extend_from_slice(&alg_id.to_be_bytes());
    sel.push(3);
    let mut bitmap = [0u8; 3];
    for v in &sorted {
        if v.index < 24 {
            bitmap[(v.index / 8) as usize] |= 1 << (v.index % 8);
        }
    }
    sel.extend_from_slice(&bitmap);

    let mut h = Sha256::new();
    h.update([0u8; 32]);
    h.update(TPM_CC_POLICY_PCR.to_be_bytes());
    h.update(&sel);
    h.update(&pcr_digest);
    Ok(h.finalize().to_vec())
}

/// Fold a measurement into a PCR value in software: `H(pcr ‖ digest)`.
/// Used by software/mock backends to mirror TPM2_PCR_Extend.
pub fn pcr_fold(bank: &str, current: &[u8], digest: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(current.len() + digest.len());
    buf.extend_from_slice(current);
    buf.extend_from_slice(digest);
    hash_for_bank(bank, &buf)
}
