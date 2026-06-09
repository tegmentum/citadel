//! A software-modeled **TPM 1.2** backend — the 1.2 tier for development and
//! testing (TPM 1.2/2.0 support, T2). It advertises the 1.2 spec + capabilities
//! (RSA-only, SHA-1 PCRs, no policy sessions); key / PCR / NV / quote operations
//! run against an in-process model, while the 2.0-only policy operations
//! (`approve_policy`, `sign_authorized`, `unseal_authorized`, policy-bound keys)
//! inherit the trait's `bail!` default — exactly a 1.2 device's limits.
//!
//! A real 1.2 device binds via a TrouSerS / TSS 1.2 shim (deployment), the same
//! way `HardwareBackend` binds a real 2.0 device via tss-esapi.

use crate::model::{Algorithm, ObjectPath};

use super::mock::MockBackend;
use super::traits::{
    BackendStatus, Capabilities, KeyHandle, PcrValue, QuoteData, QuoteVerification, SealedData,
    SpecVersion, TpmBackend,
};

/// The TPM 1.2 tier backend.
pub struct Tpm12Backend {
    inner: MockBackend,
}

impl Tpm12Backend {
    pub fn new() -> Self {
        Tpm12Backend {
            inner: MockBackend::new(),
        }
    }
}

impl Default for Tpm12Backend {
    fn default() -> Self {
        Self::new()
    }
}

fn reject_ecc(algorithm: Algorithm) -> anyhow::Result<()> {
    if matches!(algorithm, Algorithm::EccP256 | Algorithm::EccP384) {
        anyhow::bail!("TPM 1.2 is RSA-only; ECC keys are not supported (use rsa2048/rsa3072)");
    }
    Ok(())
}

impl TpmBackend for Tpm12Backend {
    fn status(&self) -> anyhow::Result<BackendStatus> {
        Ok(BackendStatus {
            backend_type: "tpm12".to_string(),
            manufacturer: "Software TPM 1.2 model".to_string(),
            firmware_version: "1.2".to_string(),
            available: true,
            spec_version: SpecVersion::Tpm12,
            capabilities: Capabilities::tpm12(),
        })
    }

    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle> {
        reject_ecc(algorithm)?;
        self.inner.create_key(algorithm, path)
    }

    fn create_ak(&self, algorithm: Algorithm) -> anyhow::Result<KeyHandle> {
        reject_ecc(algorithm)?;
        self.inner.create_ak(algorithm)
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.inner.sign(handle, data)
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>> {
        self.inner.list_handles()
    }

    fn seal(&self, data: &[u8], policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData> {
        self.inner.seal(data, policy_digest)
    }

    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>> {
        self.inner.unseal(sealed)
    }

    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>> {
        self.inner.pcr_read(bank, indices)
    }

    fn pcr_extend(&self, bank: &str, index: u32, digest: &[u8]) -> anyhow::Result<()> {
        self.inner.pcr_extend(bank, index, digest)
    }

    fn nv_define(&self, index: u32, size: usize) -> anyhow::Result<()> {
        self.inner.nv_define(index, size)
    }

    fn nv_write(&self, index: u32, data: &[u8]) -> anyhow::Result<()> {
        self.inner.nv_write(index, data)
    }

    fn nv_read(&self, index: u32, size: usize) -> anyhow::Result<Vec<u8>> {
        self.inner.nv_read(index, size)
    }

    fn nv_undefine(&self, index: u32) -> anyhow::Result<()> {
        self.inner.nv_undefine(index)
    }

    fn quote(
        &self,
        ak_handle: &KeyHandle,
        nonce: &[u8],
        pcr_bank: &str,
        pcr_indices: &[u32],
    ) -> anyhow::Result<QuoteData> {
        self.inner.quote(ak_handle, nonce, pcr_bank, pcr_indices)
    }

    fn verify_quote(
        &self,
        quote: &QuoteData,
        ak_public: &[u8],
        nonce: &[u8],
    ) -> anyhow::Result<QuoteVerification> {
        self.inner.verify_quote(quote, ak_public, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SpecVersion;

    #[test]
    fn reports_the_tpm12_tier_and_gates_ecc() {
        let b = Tpm12Backend::new();
        let s = b.status().unwrap();
        assert_eq!(s.spec_version, SpecVersion::Tpm12);
        assert!(!s.capabilities.ecc && !s.capabilities.policy_authorize);
        assert!(s.capabilities.supports_bank("sha1") && !s.capabilities.supports_bank("sha256"));

        // RSA keys work; ECC is rejected (1.2 is RSA-only).
        let path = ObjectPath::new("k/rsa").unwrap();
        assert!(b.create_key(Algorithm::Rsa2048, &path).is_ok());
        assert!(b
            .create_key(Algorithm::EccP256, &ObjectPath::new("k/ecc").unwrap())
            .is_err());
    }

    #[test]
    fn tpm12_conformance_rsa_quote_seal_nv() {
        // The full TPM 1.2-supported surface, mirroring the 2.0 conformance path:
        // RSA key + sign/verify, AK + SHA-1 quote + verify, seal/unseal, NV.
        let b = Tpm12Backend::new();

        let h = b
            .create_key(Algorithm::Rsa2048, &ObjectPath::new("conf/rsa").unwrap())
            .unwrap();
        let sig = b.sign(&h, b"data").unwrap();
        assert!(b.verify_signature(&h, b"data", &sig).unwrap());

        let ak = b.create_ak(Algorithm::Rsa2048).unwrap();
        b.pcr_extend("sha1", 7, &[0xAB; 20]).unwrap();
        let quote = b.quote(&ak, b"nonce-12", "sha1", &[0, 7]).unwrap();
        let ak_pub = b.public_blob(&ak).unwrap();
        let v = b.verify_quote(&quote, &ak_pub, b"nonce-12").unwrap();
        assert!(v.verified && v.signature_valid && v.nonce_matches);

        let sealed = b.seal(b"top-secret", None).unwrap();
        assert_eq!(b.unseal(&sealed).unwrap(), b"top-secret");

        b.nv_define(0x1500001, 8).unwrap();
        b.nv_write(0x1500001, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(
            b.nv_read(0x1500001, 8).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn sha1_measured_boot_works_but_policy_authorize_does_not() {
        let b = Tpm12Backend::new();
        // SHA-1 PCR extend (the 1.2 bank) works.
        let digest = vec![0u8; 20];
        assert!(b.pcr_extend("sha1", 7, &digest).is_ok());
        assert!(!b.pcr_read("sha1", &[7]).unwrap().is_empty());

        // The 2.0-only TPM-enforced unseal (MSS S0) is unavailable on 1.2.
        let sealed = b.seal(b"secret", None).unwrap();
        assert!(b.unseal(&sealed).is_ok());
        assert!(b
            .unseal_authorized(&sealed, b"auth", b"policy", b"ref", b"sig")
            .is_err());
    }
}
