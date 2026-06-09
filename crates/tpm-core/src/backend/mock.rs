use std::collections::HashMap;
use std::sync::Mutex;

use crate::model::{Algorithm, ObjectPath};

use super::traits::{
    bank_digest_size, hash_for_bank, pcr_fold, BackendStatus, KeyHandle, PcrValue, SealedData,
    TpmBackend,
};

/// The aHash an authority signs to approve a policy: `H(approvedPolicy ‖ policyRef)`.
fn approval_ahash(approved_policy: &[u8], policy_ref: &[u8]) -> Vec<u8> {
    let mut buf = approved_policy.to_vec();
    buf.extend_from_slice(policy_ref);
    hash_for_bank("sha256", &buf).expect("sha256 available")
}

/// Deterministic mock backend for development and testing.
pub struct MockBackend {
    keys: Mutex<HashMap<String, MockKey>>,
    nv: Mutex<HashMap<u32, NvSlot>>,
    /// PCR values that have been extended this session, keyed by
    /// (bank, index). Indices absent here read back as their
    /// deterministic default (see `pcr_default`).
    pcrs: Mutex<HashMap<(String, u32), Vec<u8>>>,
    /// Monotonic NV counters, keyed by index. Increment-only.
    counters: Mutex<HashMap<u32, u64>>,
    /// authPolicy a key was bound to (key id -> PolicyPCR digest), so
    /// `sign_with_policy` can enforce the measured-state gate in software.
    key_policies: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    /// Ordered record of measurements, per `(bank, index)`, so a replayable
    /// event log can be synthesized (`read_event_log`).
    extends: Mutex<HashMap<(String, u32), Vec<RecordedExtend>>>,
}

/// One recorded measurement for event-log synthesis.
struct RecordedExtend {
    digest: Vec<u8>,
    /// Event data (e.g. a kernel command line); empty for a bare `pcr_extend`.
    data: Vec<u8>,
    /// TCG event type, when measured via [`MockBackend::measure_event`].
    tcg_type: Option<u32>,
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
            pcrs: Mutex::new(HashMap::new()),
            counters: Mutex::new(HashMap::new()),
            key_policies: Mutex::new(HashMap::new()),
            extends: Mutex::new(HashMap::new()),
        }
    }

    /// Deterministic per-index default value for a not-yet-extended PCR.
    /// Preserves the historical mock pattern so existing read/quote
    /// behavior is unchanged until an explicit `pcr_extend`.
    fn pcr_default(index: u32) -> Vec<u8> {
        let mut digest = vec![0u8; 32];
        digest[0] = index as u8;
        digest[1] = 0xAB;
        digest[31] = index as u8;
        digest
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
            spec_version: super::traits::SpecVersion::Tpm20,
            capabilities: super::traits::Capabilities::tpm20(),
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
        // Deterministic signature from handle ID + data.
        // Does not require the key to be in the in-memory map since
        // keys persist across invocations via the store's handle_blob.
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

    fn create_key_with_policy(
        &self,
        algorithm: Algorithm,
        path: &ObjectPath,
        auth_policy: &[u8],
    ) -> anyhow::Result<KeyHandle> {
        let handle = self.create_key(algorithm, path)?;
        self.key_policies
            .lock()
            .unwrap()
            .insert(handle.id.clone(), auth_policy.to_vec());
        Ok(handle)
    }

    fn sign_with_policy(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        bank: &str,
        indices: &[u32],
    ) -> anyhow::Result<Vec<u8>> {
        let expected = self
            .key_policies
            .lock()
            .unwrap()
            .get(&handle.id)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("policy-bound key not known to this mock backend instance")
            })?;
        // Software enforcement mirroring the TPM: the current PolicyPCR
        // digest must match what the key was bound to.
        let current = self.pcr_policy_digest(bank, indices)?;
        if current != expected {
            anyhow::bail!(
                "measured-state policy not satisfied: {} PCR {:?} differ from the bound state",
                bank,
                indices
            );
        }
        self.sign(handle, data)
    }

    fn create_authority_key(
        &self,
        algorithm: Algorithm,
        path: &ObjectPath,
    ) -> anyhow::Result<KeyHandle> {
        self.create_key(algorithm, path)
    }

    fn create_key_authorized(
        &self,
        algorithm: Algorithm,
        path: &ObjectPath,
        _authority_pub: &[u8],
    ) -> anyhow::Result<KeyHandle> {
        // Mock: a normal key; the state + approval checks are enforced in
        // sign_authorized (a real TPM enforces them via authPolicy).
        self.create_key(algorithm, path)
    }

    fn approve_policy(
        &self,
        authority: &KeyHandle,
        approved_policy: &[u8],
        policy_ref: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        self.sign(authority, &approval_ahash(approved_policy, policy_ref))
    }

    fn sign_authorized(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        bank: &str,
        indices: &[u32],
        authority_pub: &[u8],
        approved_policy: &[u8],
        policy_ref: &[u8],
        approval_sig: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // The current measured state must equal the approved one.
        if self.pcr_policy_digest(bank, indices)? != approved_policy {
            anyhow::bail!(
                "measured-state policy not satisfied: current state differs from the approval"
            );
        }
        // The authority must have signed the approval.
        let ahash = approval_ahash(approved_policy, policy_ref);
        let authority = KeyHandle {
            id: authority_pub.to_vec(),
            path: String::new(),
        };
        if !self.verify_signature(&authority, &ahash, approval_sig)? {
            anyhow::bail!("approval signature does not verify");
        }
        self.sign(handle, data)
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

    fn unseal_authorized(
        &self,
        sealed: &SealedData,
        authority_pub: &[u8],
        approved_policy: &[u8],
        policy_ref: &[u8],
        approval_sig: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // The blob must have been sealed under the approved policy.
        if sealed.policy_digest.as_deref() != Some(approved_policy) {
            anyhow::bail!("sealed policy does not match the approved policy");
        }
        // The authority must have signed the approval.
        let ahash = approval_ahash(approved_policy, policy_ref);
        let authority = KeyHandle {
            id: authority_pub.to_vec(),
            path: String::new(),
        };
        if !self.verify_signature(&authority, &ahash, approval_sig)? {
            anyhow::bail!("approval signature does not verify");
        }
        self.unseal(sealed)
    }

    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>> {
        let pcrs = self.pcrs.lock().unwrap();
        Ok(indices
            .iter()
            .map(|&idx| {
                // Return the extended value if present, else the
                // deterministic default for this index.
                let digest = pcrs
                    .get(&(bank.to_string(), idx))
                    .cloned()
                    .unwrap_or_else(|| Self::pcr_default(idx));
                PcrValue {
                    bank: bank.to_string(),
                    index: idx,
                    digest,
                }
            })
            .collect())
    }

    fn pcr_extend(&self, bank: &str, index: u32, digest: &[u8]) -> anyhow::Result<()> {
        let expected = bank_digest_size(bank)?;
        if digest.len() != expected {
            anyhow::bail!(
                "pcr_extend: digest is {} bytes, expected {} for bank '{}'",
                digest.len(),
                expected,
                bank
            );
        }
        let mut pcrs = self.pcrs.lock().unwrap();
        let key = (bank.to_string(), index);
        let current = pcrs
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Self::pcr_default(index));
        let folded = pcr_fold(bank, &current, digest)?;
        pcrs.insert(key.clone(), folded);
        // Record the digest so a replayable event log can be synthesized.
        self.extends
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .push(RecordedExtend {
                digest: digest.to_vec(),
                data: Vec::new(),
                tcg_type: None,
            });
        Ok(())
    }

    /// Measure raw `data` into a PCR and record the data + TCG `event_type`, so
    /// the synthesized event log carries a digest-bound, classifiable event
    /// (e.g. an `EV_IPL` kernel command line). Testing aid for the event-log
    /// semantic path.
    fn measure_event(
        &self,
        bank: &str,
        index: u32,
        event_type: u32,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let digest = hash_for_bank(bank, data)?;
        self.pcr_extend(bank, index, &digest)?;
        let mut extends = self.extends.lock().unwrap();
        if let Some(rec) = extends
            .get_mut(&(bank.to_string(), index))
            .and_then(|v| v.last_mut())
        {
            rec.data = data.to_vec();
            rec.tcg_type = Some(event_type);
        }
        Ok(())
    }

    /// Synthesize a measured-boot event log that replays to this backend's
    /// current PCR state: a `NoAction` base event per standard PCR (its
    /// pre-extend default), then an `Extend` event per recorded `pcr_extend`.
    /// So `replay(log) == pcr_read(...)` for every PCR — making the event-log
    /// path deterministically testable without real hardware.
    fn read_event_log(&self) -> anyhow::Result<Option<Vec<u8>>> {
        use crate::eventlog::{BootEventLog, EventType, MeasurementEvent};
        let bank = "sha256";
        let extends = self.extends.lock().unwrap();
        let mut events = Vec::new();
        // Base events: every standard PCR starts at its deterministic default.
        for index in 0u32..24 {
            events.push(MeasurementEvent {
                pcr: index,
                event_type: EventType::Base,
                digests: vec![(bank.to_string(), Self::pcr_default(index))],
                data: Vec::new(),
            });
        }
        // Extend events, grouped by PCR, in recorded order.
        let mut keys: Vec<&(String, u32)> = extends.keys().collect();
        keys.sort();
        for key in keys {
            if key.0 != bank {
                continue;
            }
            for rec in &extends[key] {
                events.push(MeasurementEvent {
                    pcr: key.1,
                    event_type: match rec.tcg_type {
                        Some(t) => EventType::Unknown(t),
                        None => EventType::Extend,
                    },
                    digests: vec![(bank.to_string(), rec.digest.clone())],
                    data: rec.data.clone(),
                });
            }
        }
        Ok(Some(BootEventLog::new(events).to_bytes()))
    }

    fn nv_define(&self, index: u32, size: usize) -> anyhow::Result<()> {
        let mut nv = self.nv.lock().unwrap();
        if nv.contains_key(&index) {
            // Already defined in this process — that's fine
            return Ok(());
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
        nv.remove(&index);
        Ok(())
    }

    fn nv_increment(&self, index: u32) -> anyhow::Result<u64> {
        let mut counters = self.counters.lock().unwrap();
        let v = counters.entry(index).or_insert(0);
        *v += 1; // increment-only, mirroring a TPM counter-type NV index
        Ok(*v)
    }

    fn nv_read_counter(&self, index: u32) -> anyhow::Result<Option<u64>> {
        Ok(self.counters.lock().unwrap().get(&index).copied())
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
                let c_hex: String = current
                    .digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::traits::{Capabilities, SpecVersion};

    fn d(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn mock_advertises_tpm20_full_capabilities() {
        let s = MockBackend::new().status().unwrap();
        assert_eq!(s.spec_version, SpecVersion::Tpm20);
        assert!(s.capabilities.ecc);
        assert!(s.capabilities.policy_authorize);
        assert!(s.capabilities.supports_bank("sha256"));
        assert!(s.capabilities.supports_algorithm(Algorithm::EccP256));
    }

    #[test]
    fn tpm12_capabilities_gate_ec_and_policy_authorize() {
        let c = Capabilities::tpm12();
        assert!(!c.ecc, "1.2 is RSA-only");
        assert!(
            !c.policy_authorize && !c.policy_sessions,
            "1.2 has no policy sessions"
        );
        assert!(c.supports_bank("sha1") && !c.supports_bank("sha256"));
        assert!(c.supports_algorithm(Algorithm::Rsa2048));
        assert!(!c.supports_algorithm(Algorithm::EccP256));
    }

    #[test]
    fn unseal_authorized_requires_the_authority_approval() {
        use crate::model::{Algorithm, ObjectPath};
        let tpm = MockBackend::new();
        let policy = d(0x5e); // the secret's release policy digest
        let policy_ref = b"nonce-abc";
        let sealed = tpm.seal(b"db-prod-password", Some(&policy)).unwrap();

        // The release authority approves this policy.
        let authority = tpm
            .create_key(
                Algorithm::EccP256,
                &ObjectPath::new("mss/authority").unwrap(),
            )
            .unwrap();
        let approval = tpm.approve_policy(&authority, &policy, policy_ref).unwrap();

        // With the approval, the blob unseals.
        assert_eq!(
            tpm.unseal_authorized(&sealed, &authority.id, &policy, policy_ref, &approval)
                .unwrap(),
            b"db-prod-password"
        );

        // A wrong/missing approval is refused...
        assert!(tpm
            .unseal_authorized(&sealed, &authority.id, &policy, policy_ref, b"forged")
            .is_err());
        // ...as is an approval over a different policy than the blob was sealed under.
        let other = d(0x99);
        let approval2 = tpm.approve_policy(&authority, &other, policy_ref).unwrap();
        assert!(tpm
            .unseal_authorized(&sealed, &authority.id, &other, policy_ref, &approval2)
            .is_err());
    }

    #[test]
    fn extend_changes_pcr_and_is_deterministic() {
        let a = MockBackend::new();
        let before = a.pcr_read("sha256", &[10]).unwrap()[0].digest.clone();
        a.pcr_extend("sha256", 10, &d(0x11)).unwrap();
        let after = a.pcr_read("sha256", &[10]).unwrap()[0].digest.clone();
        assert_ne!(before, after, "extend must change the PCR value");

        // Same sequence on a fresh backend yields the same value.
        let b = MockBackend::new();
        b.pcr_extend("sha256", 10, &d(0x11)).unwrap();
        assert_eq!(after, b.pcr_read("sha256", &[10]).unwrap()[0].digest);
    }

    #[test]
    fn extend_is_order_dependent() {
        let a = MockBackend::new();
        a.pcr_extend("sha256", 0, &d(0x01)).unwrap();
        a.pcr_extend("sha256", 0, &d(0x02)).unwrap();

        let b = MockBackend::new();
        b.pcr_extend("sha256", 0, &d(0x02)).unwrap();
        b.pcr_extend("sha256", 0, &d(0x01)).unwrap();

        assert_ne!(
            a.pcr_read("sha256", &[0]).unwrap()[0].digest,
            b.pcr_read("sha256", &[0]).unwrap()[0].digest,
            "PCR extend must be order-dependent"
        );
    }

    #[test]
    fn extend_rejects_wrong_digest_size() {
        let a = MockBackend::new();
        assert!(a.pcr_extend("sha256", 0, &[0u8; 16]).is_err());
    }

    #[test]
    fn nv_counter_is_monotonic_per_index() {
        let a = MockBackend::new();
        assert_eq!(a.nv_increment(0x0180_0001).unwrap(), 1);
        assert_eq!(a.nv_increment(0x0180_0001).unwrap(), 2);
        assert_eq!(a.nv_increment(0x0180_0001).unwrap(), 3);
        // A different index counts independently.
        assert_eq!(a.nv_increment(0x0180_0002).unwrap(), 1);
        assert_eq!(a.nv_increment(0x0180_0001).unwrap(), 4);
    }

    #[test]
    fn extend_isolated_per_index() {
        let a = MockBackend::new();
        let untouched = a.pcr_read("sha256", &[5]).unwrap()[0].digest.clone();
        a.pcr_extend("sha256", 0, &d(0xFF)).unwrap();
        assert_eq!(
            untouched,
            a.pcr_read("sha256", &[5]).unwrap()[0].digest,
            "extending PCR 0 must not affect PCR 5"
        );
    }
}
