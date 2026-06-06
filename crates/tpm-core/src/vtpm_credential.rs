//! vTPM endorsement credential.
//!
//! Provisioning binds a vTPM instance to a hardware TPM by having the hw-TPM
//! attestation key sign a small statement of identity (`signed_data`). Once
//! written, the credential travels with the vTPM and the hw-TPM is no longer
//! required for the vTPM to operate — only for re-verification.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Schema version for forward compatibility.
pub const VTPM_CREDENTIAL_VERSION: u8 = 1;

/// The signed identity payload, kept separate from any TPM-specific blobs so
/// it can be reconstructed deterministically by a verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtpmIdentity {
    pub instance_id: String,
    pub created_at: String,
    pub vtpm_label: String,
    /// The vTPM's attestation-key public, when the hardware endorsement is to
    /// **cover the per-quote AK** (not just the instance identity). Omitted —
    /// and byte-identical to v1 — when absent, so existing credentials and
    /// their signatures are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ak_public: Option<Vec<u8>>,
}

impl VtpmIdentity {
    /// A bare instance identity (no AK binding).
    pub fn new(instance_id: String, created_at: String, vtpm_label: String) -> Self {
        VtpmIdentity {
            instance_id,
            created_at,
            vtpm_label,
            ak_public: None,
        }
    }

    /// Bind this identity to the vTPM's attestation key, so the hardware
    /// signature covers the AK that signs quotes.
    pub fn with_ak(mut self, ak_public: Vec<u8>) -> Self {
        self.ak_public = Some(ak_public);
        self
    }

    /// Deterministic CBOR encoding of the identity, used as the message that
    /// the hw-TPM signs.
    pub fn to_signed_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| anyhow::anyhow!("encode identity: {}", e))?;
        Ok(buf)
    }
}

/// On-disk credential. The `hw_ak_pub` and `signature` blobs are TPM2B-format
/// bytes as produced by tss-esapi `marshall()`; treat them as opaque except
/// when verifying through the same backend that produced them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtpmCredential {
    pub version: u8,
    pub identity: VtpmIdentity,
    pub hw_backend_label: String,
    #[serde(with = "hex_bytes")]
    pub signed_data: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub hw_ak_pub: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

impl VtpmCredential {
    pub fn new(
        identity: VtpmIdentity,
        hw_backend_label: String,
        hw_ak_pub: Vec<u8>,
        signature: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let signed_data = identity.to_signed_bytes()?;
        Ok(Self {
            version: VTPM_CREDENTIAL_VERSION,
            identity,
            hw_backend_label,
            signed_data,
            hw_ak_pub,
            signature,
        })
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("read {}: {}", path.display(), e))?;
        let cred: VtpmCredential = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parse {}: {}", path.display(), e))?;
        if cred.version != VTPM_CREDENTIAL_VERSION {
            anyhow::bail!(
                "unsupported vTPM credential version {} (expected {})",
                cred.version,
                VTPM_CREDENTIAL_VERSION
            );
        }
        let recomputed = cred.identity.to_signed_bytes()?;
        if recomputed != cred.signed_data {
            anyhow::bail!("credential signed_data does not match identity fields");
        }
        Ok(cred)
    }
}

/// Default credential path: `$XDG_DATA_HOME/tpm/vtpm-credential.json` or
/// `~/.local/share/tpm/vtpm-credential.json`.
pub fn default_credential_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(dir).join("tpm").join("vtpm-credential.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("tpm")
            .join("vtpm-credential.json");
    }
    PathBuf::from("vtpm-credential.json")
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(v.len() * 2);
        for b in v {
            out.push_str(&format!("{:02x}", b));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd hex length"));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| serde::de::Error::custom(format!("bad hex: {}", e)))?;
            out.push(byte);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_credential() {
        let id = VtpmIdentity::new(
            "abc-123".to_string(),
            "2026-04-23T00:00:00Z".to_string(),
            "vtpm-wasm".to_string(),
        );
        let cred = VtpmCredential::new(
            id,
            "swtpm".to_string(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred.json");
        cred.save(&path).unwrap();
        let loaded = VtpmCredential::load(&path).unwrap();
        assert_eq!(loaded.identity.instance_id, "abc-123");
        assert_eq!(loaded.signed_data, cred.signed_data);
        assert_eq!(loaded.hw_ak_pub, vec![1, 2, 3, 4]);
        assert_eq!(loaded.signature, vec![5, 6, 7, 8]);
    }

    #[test]
    fn rejects_tampered_signed_data() {
        let id = VtpmIdentity::new(
            "abc-123".to_string(),
            "2026-04-23T00:00:00Z".to_string(),
            "vtpm-wasm".to_string(),
        );
        let mut cred = VtpmCredential::new(
            id,
            "swtpm".to_string(),
            vec![1],
            vec![2],
        )
        .unwrap();
        cred.identity.instance_id = "different".to_string();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred.json");
        cred.save(&path).unwrap();
        let err = VtpmCredential::load(&path).unwrap_err();
        assert!(err.to_string().contains("signed_data"));
    }

    #[test]
    fn ak_binding_is_covered_by_signed_data() {
        let base = VtpmIdentity::new(
            "abc-123".to_string(),
            "2026-04-23T00:00:00Z".to_string(),
            "vtpm-wasm".to_string(),
        );
        // An AK-less identity encodes byte-identically to v1 (no ak field).
        let bound = base.clone().with_ak(vec![0xAB, 0xCD, 0xEF]);
        assert_ne!(
            base.to_signed_bytes().unwrap(),
            bound.to_signed_bytes().unwrap(),
            "binding the AK must change what the hardware signs"
        );
        // The bound credential round-trips and preserves the AK.
        let cred = VtpmCredential::new(bound, "swtpm".to_string(), vec![1], vec![2]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred.json");
        cred.save(&path).unwrap();
        let loaded = VtpmCredential::load(&path).unwrap();
        assert_eq!(loaded.identity.ak_public, Some(vec![0xAB, 0xCD, 0xEF]));
        assert_eq!(loaded.signed_data, cred.signed_data);
    }
}
