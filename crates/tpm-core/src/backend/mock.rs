use std::collections::HashMap;
use std::sync::Mutex;

use crate::model::{Algorithm, ObjectPath};

use super::traits::{BackendStatus, KeyHandle, PcrValue, SealedData, TpmBackend};

/// Deterministic mock backend for development and testing.
pub struct MockBackend {
    keys: Mutex<HashMap<String, MockKey>>,
    nv: Mutex<HashMap<u32, NvSlot>>,
}

struct MockKey {
    #[allow(dead_code)]
    algorithm: Algorithm,
    id: Vec<u8>,
}

struct NvSlot {
    size: usize,
    data: Option<Vec<u8>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            nv: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmBackend for MockBackend {
    fn status(&self) -> anyhow::Result<BackendStatus> {
        Ok(BackendStatus {
            backend_type: "mock".to_string(),
            manufacturer: "Mock TPM".to_string(),
            firmware_version: "0.0.0".to_string(),
            available: true,
        })
    }

    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle> {
        let mut keys = self.keys.lock().unwrap();
        let id: Vec<u8> = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            path.as_str().hash(&mut h);
            h.finish().to_le_bytes().to_vec()
        };
        keys.insert(
            path.as_str().to_string(),
            MockKey {
                algorithm,
                id: id.clone(),
            },
        );
        Ok(KeyHandle {
            id,
            path: path.as_str().to_string(),
        })
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let keys = self.keys.lock().unwrap();
        if !keys.contains_key(&handle.path) {
            anyhow::bail!("key not found: {}", handle.path);
        }
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        handle.id.hash(&mut h);
        data.hash(&mut h);
        Ok(h.finish().to_le_bytes().to_vec())
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>> {
        let keys = self.keys.lock().unwrap();
        Ok(keys
            .iter()
            .map(|(path, key)| KeyHandle {
                id: key.id.clone(),
                path: path.clone(),
            })
            .collect())
    }

    fn seal(&self, data: &[u8], policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData> {
        // Mock: XOR data with a fixed key to simulate encryption
        let blob: Vec<u8> = data.iter().map(|b| b ^ 0xAA).collect();
        Ok(SealedData {
            blob,
            policy_digest: policy_digest.map(|d| d.to_vec()),
        })
    }

    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>> {
        // Mock: reverse the XOR
        Ok(sealed.blob.iter().map(|b| b ^ 0xAA).collect())
    }

    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>> {
        // Mock: return deterministic PCR values
        Ok(indices
            .iter()
            .map(|&idx| {
                let mut digest = vec![0u8; 32];
                // Deterministic: each PCR has a unique pattern
                digest[0] = idx as u8;
                digest[1] = 0xAB;
                digest[31] = idx as u8;
                PcrValue {
                    bank: bank.to_string(),
                    index: idx,
                    digest,
                }
            })
            .collect())
    }

    fn nv_define(&self, index: u32, size: usize) -> anyhow::Result<()> {
        let mut nv = self.nv.lock().unwrap();
        if nv.contains_key(&index) {
            anyhow::bail!("NV index 0x{:08X} already defined", index);
        }
        nv.insert(index, NvSlot { size, data: None });
        Ok(())
    }

    fn nv_write(&self, index: u32, data: &[u8]) -> anyhow::Result<()> {
        let mut nv = self.nv.lock().unwrap();
        let slot = nv
            .get_mut(&index)
            .ok_or_else(|| anyhow::anyhow!("NV index 0x{:08X} not defined", index))?;
        if data.len() > slot.size {
            anyhow::bail!(
                "data ({} bytes) exceeds NV index size ({} bytes)",
                data.len(),
                slot.size
            );
        }
        slot.data = Some(data.to_vec());
        Ok(())
    }

    fn nv_read(&self, index: u32, size: usize) -> anyhow::Result<Vec<u8>> {
        let nv = self.nv.lock().unwrap();
        let slot = nv
            .get(&index)
            .ok_or_else(|| anyhow::anyhow!("NV index 0x{:08X} not defined", index))?;
        match &slot.data {
            Some(data) => {
                let read_size = size.min(data.len());
                Ok(data[..read_size].to_vec())
            }
            None => anyhow::bail!("NV index 0x{:08X} has not been written", index),
        }
    }

    fn nv_undefine(&self, index: u32) -> anyhow::Result<()> {
        let mut nv = self.nv.lock().unwrap();
        if nv.remove(&index).is_none() {
            anyhow::bail!("NV index 0x{:08X} not defined", index);
        }
        Ok(())
    }

    fn create_ak(&self, algorithm: Algorithm) -> anyhow::Result<KeyHandle> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        "ak".hash(&mut h);
        algorithm.to_string().hash(&mut h);
        let id = h.finish().to_le_bytes().to_vec();
        Ok(KeyHandle {
            id,
            path: "(ak)".to_string(),
        })
    }

    fn quote(
        &self,
        ak_handle: &KeyHandle,
        nonce: &[u8],
        pcr_bank: &str,
        pcr_indices: &[u32],
    ) -> anyhow::Result<super::traits::QuoteData> {
        let pcr_values = self.pcr_read(pcr_bank, pcr_indices)?;

        // Mock attestation: hash of PCR values + nonce
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        for v in &pcr_values {
            v.digest.hash(&mut h);
        }
        nonce.hash(&mut h);
        let attestation = h.finish().to_le_bytes().to_vec();

        // Mock signature: hash of attestation + ak
        let mut h2 = DefaultHasher::new();
        attestation.hash(&mut h2);
        ak_handle.id.hash(&mut h2);
        let signature = h2.finish().to_le_bytes().to_vec();

        Ok(super::traits::QuoteData {
            attestation,
            signature,
            pcr_values,
            nonce: nonce.to_vec(),
            ak_public: ak_handle.id.clone(),
        })
    }

    fn verify_quote(
        &self,
        quote: &super::traits::QuoteData,
        ak_public: &[u8],
        nonce: &[u8],
    ) -> anyhow::Result<super::traits::QuoteVerification> {
        // Verify nonce
        let nonce_matches = quote.nonce == nonce;

        // Verify signature (mock: recompute)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        quote.attestation.hash(&mut h);
        ak_public.hash(&mut h);
        let expected_sig = h.finish().to_le_bytes().to_vec();
        let signature_valid = quote.signature == expected_sig;

        // Compare PCR values against current state
        let current_pcrs = if let Some(first) = quote.pcr_values.first() {
            let indices: Vec<u32> = quote.pcr_values.iter().map(|v| v.index).collect();
            self.pcr_read(&first.bank, &indices)?
        } else {
            Vec::new()
        };

        let pcr_matches: Vec<super::traits::PcrMatchResult> = quote
            .pcr_values
            .iter()
            .zip(current_pcrs.iter())
            .map(|(quoted, current)| {
                let q_hex: String = quoted.digest.iter().map(|b| format!("{:02x}", b)).collect();
                let c_hex: String =
                    current.digest.iter().map(|b| format!("{:02x}", b)).collect();
                super::traits::PcrMatchResult {
                    index: quoted.index,
                    bank: quoted.bank.clone(),
                    expected: q_hex.clone(),
                    actual: c_hex.clone(),
                    matches: q_hex == c_hex,
                }
            })
            .collect();

        let all_pcrs_match = pcr_matches.iter().all(|m| m.matches);
        let verified = signature_valid && nonce_matches && all_pcrs_match;

        Ok(super::traits::QuoteVerification {
            signature_valid,
            nonce_matches,
            pcr_matches,
            verified,
        })
    }
}
