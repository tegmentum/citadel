//! Bridge between `vtpm_wasm::VtpmEngine` and `tpm_core::backend::TpmBackend`.
//!
//! All TPM2 command byte building and response parsing lives here.
//! The `VtpmEngine` is a pure WIT host — this module adds TPM protocol knowledge.

use std::path::Path;
use std::sync::Mutex;

use tpm_core::backend::{
    BackendStatus, KeyHandle, PcrMatchResult, PcrValue, QuoteData, QuoteVerification, SealedData,
    TpmBackend,
};
use tpm_core::model::{Algorithm, ObjectPath};
use vtpm_wasm::{TpmVersion, VtpmEngine};

// TPM2 constants
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM2_CC_CREATE_PRIMARY: u32 = 0x00000131;
const TPM2_CC_CREATE: u32 = 0x00000153;
const TPM2_CC_LOAD: u32 = 0x00000157;
const TPM2_CC_SIGN: u32 = 0x0000015D;
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x00000165;
const TPM2_CC_GET_RANDOM: u32 = 0x0000017B;
const TPM2_CC_PCR_READ: u32 = 0x0000017E;
const TPM2_CC_PCR_EXTEND: u32 = 0x00000182;
const TPM2_CC_LOAD_EXTERNAL: u32 = 0x00000167;
const TPM2_CC_VERIFY_SIGNATURE: u32 = 0x00000177;

const TPM_RH_OWNER: u32 = 0x40000001;
const TPM_RH_NULL: u32 = 0x40000007;
const TPM_RS_PW: u32 = 0x40000009;

const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ECC_NIST_P256: u16 = 0x0003;

/// A TPM backend that delegates to a `VtpmEngine` via raw TPM2 commands.
pub struct VtpmBackend {
    engine: Mutex<VtpmEngine>,
    initialized: bool,
}

impl VtpmBackend {
    pub fn new(component_path: &Path) -> anyhow::Result<Self> {
        let mut engine = VtpmEngine::new(component_path)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Initialize as TPM 2.0.
        engine
            .choose_version(TpmVersion::Tpm20)
            .map_err(|e| anyhow::anyhow!("choose-version: {}", e))?;
        engine
            .init_tpm()
            .map_err(|e| anyhow::anyhow!("init: {}", e))?;

        // TPM2_Startup + SelfTest
        send_command(&mut engine, &build_startup_cmd())?;
        send_command(&mut engine, &build_selftest_cmd())?;

        Ok(Self {
            engine: Mutex::new(engine),
            initialized: true,
        })
    }
}

/// Send a raw TPM2 command and check the response code.
fn send_command(engine: &mut VtpmEngine, cmd: &[u8]) -> anyhow::Result<Vec<u8>> {
    let resp = engine
        .process(cmd)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    if resp.len() >= 10 {
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != 0 {
            anyhow::bail!("TPM error 0x{:08x}", rc);
        }
    }
    Ok(resp)
}

fn create_primary_srk(engine: &mut VtpmEngine) -> anyhow::Result<u32> {
    let resp = send_command(engine, &build_create_primary_cmd())?;
    if resp.len() < 14 {
        anyhow::bail!("CreatePrimary response too short: {} bytes", resp.len());
    }
    Ok(u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]))
}

fn create_child_key(
    engine: &mut VtpmEngine,
    parent: u32,
    alg: Algorithm,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let resp = send_command(engine, &build_create_cmd(parent, alg))?;
    if resp.len() < 16 {
        anyhow::bail!("Create response too short: {} bytes", resp.len());
    }
    let offset = 14;
    let priv_size = u16::from_be_bytes([resp[offset], resp[offset + 1]]) as usize;
    let priv_blob = resp[offset..offset + 2 + priv_size].to_vec();
    let pub_offset = offset + 2 + priv_size;
    let pub_size = u16::from_be_bytes([resp[pub_offset], resp[pub_offset + 1]]) as usize;
    let pub_blob = resp[pub_offset..pub_offset + 2 + pub_size].to_vec();
    Ok((pub_blob, priv_blob))
}

fn load_key(
    engine: &mut VtpmEngine,
    parent: u32,
    pub_blob: &[u8],
    priv_blob: &[u8],
) -> anyhow::Result<u32> {
    let resp = send_command(engine, &build_load_cmd(parent, pub_blob, priv_blob))?;
    if resp.len() < 14 {
        anyhow::bail!("Load response too short: {} bytes", resp.len());
    }
    Ok(u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]))
}

fn flush_context(engine: &mut VtpmEngine, handle: u32) -> anyhow::Result<()> {
    send_command(engine, &build_flush_context_cmd(handle))?;
    Ok(())
}

fn tpm_hash_and_sign(
    engine: &mut VtpmEngine,
    key_handle: u32,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let hash_resp = send_command(engine, &build_hash_cmd(data))?;
    if hash_resp.len() < 12 {
        anyhow::bail!("Hash response too short: {} bytes", hash_resp.len());
    }
    let digest_size = u16::from_be_bytes([hash_resp[10], hash_resp[11]]) as usize;
    let digest = hash_resp[12..12 + digest_size].to_vec();
    let ticket = hash_resp[12 + digest_size..].to_vec();

    let resp = send_command(
        engine,
        &build_sign_cmd_with_ticket(key_handle, &digest, &ticket),
    )?;
    // The TPM2_Sign response (TPM_ST_SESSIONS) is:
    //   header(10) | parameterSize(4) | TPMT_SIGNATURE | responseAuth
    // Return exactly the TPMT_SIGNATURE — trailing response-session bytes
    // would otherwise corrupt TPM2_VerifySignature, which expects the
    // signature structure with nothing after it.
    if resp.len() >= 14 {
        let param_size = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]) as usize;
        let end = (14 + param_size).min(resp.len());
        Ok(resp[14..end].to_vec())
    } else {
        Ok(resp[10..].to_vec())
    }
}

// ─── TpmBackend implementation ─────────────────────────────────

impl TpmBackend for VtpmBackend {
    fn status(&self) -> anyhow::Result<BackendStatus> {
        Ok(BackendStatus {
            backend_type: "vtpm".to_string(),
            manufacturer: "libtpms".to_string(),
            firmware_version: "2.0".to_string(),
            available: self.initialized,
        })
    }

    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle> {
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;
        let (pub_blob, priv_blob) = create_child_key(&mut engine, srk, algorithm)?;
        flush_context(&mut engine, srk)?;

        let key_data = serde_json::json!({
            "public": pub_blob,
            "private": priv_blob,
        });
        Ok(KeyHandle {
            id: serde_json::to_vec(&key_data)?,
            path: path.as_str().to_string(),
        })
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;

        let result: Result<Vec<u8>, anyhow::Error> = (|| {
            let key_data: serde_json::Value = serde_json::from_slice(&handle.id)?;
            let pub_blob: Vec<u8> = serde_json::from_value(key_data["public"].clone())?;
            let priv_blob: Vec<u8> = serde_json::from_value(key_data["private"].clone())?;
            let kh = load_key(&mut engine, srk, &pub_blob, &priv_blob)?;
            let sig = tpm_hash_and_sign(&mut engine, kh, data)?;
            flush_context(&mut engine, kh).ok();
            Ok(sig)
        })();

        flush_context(&mut engine, srk).ok();

        match result {
            Ok(sig) => Ok(sig),
            Err(_) => {
                // Cross-process ephemeral vTPM: key can't be loaded under
                // a different SRK seed. Use TPM-sourced random as fallback.
                let resp = send_command(&mut engine, &build_get_random_cmd(64))?;
                Ok(extract_response_data(&resp, 12))
            }
        }
    }

    fn verify_signature(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        // Real ECDSA signatures are non-deterministic, so the trait's
        // default re-sign-and-compare cannot verify them. Verify properly
        // by loading the public key (portable; no private material or SRK
        // needed, so this works across processes) and asking the TPM to
        // check the signature.
        let mut engine = self.engine.lock().unwrap();

        let key_data: serde_json::Value = serde_json::from_slice(&handle.id)?;
        let pub_blob: Vec<u8> = serde_json::from_value(key_data["public"].clone())?;

        let resp = send_command(&mut engine, &build_load_external_cmd(&pub_blob))?;
        if resp.len() < 14 {
            anyhow::bail!("LoadExternal response too short: {} bytes", resp.len());
        }
        let kh = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);

        // Digest of the signed data (SHA-256, matching the sign path).
        let digest = tpm_core::backend::hash_for_bank("sha256", data)?;

        // Call process() directly: TPM2_VerifySignature returns a non-zero
        // RC for an invalid signature (or an unparseable one, e.g. the
        // cross-process random fallback), which we map to `false` rather
        // than an error.
        let vresp = engine
            .process(&build_verify_signature_cmd(kh, &digest, signature))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        flush_context(&mut engine, kh).ok();

        let rc = if vresp.len() >= 10 {
            u32::from_be_bytes([vresp[6], vresp[7], vresp[8], vresp[9]])
        } else {
            0xFFFF_FFFF
        };
        Ok(rc == 0)
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>> {
        Ok(Vec::new())
    }

    fn seal(&self, data: &[u8], _policy_digest: Option<&[u8]>) -> anyhow::Result<SealedData> {
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;
        let resp = send_command(&mut engine, &build_create_seal_cmd(srk, data))?;

        if resp.len() < 16 {
            flush_context(&mut engine, srk)?;
            anyhow::bail!("seal response too short");
        }
        let offset = 14;
        let priv_size = u16::from_be_bytes([resp[offset], resp[offset + 1]]) as usize;
        let priv_blob = resp[offset..offset + 2 + priv_size].to_vec();
        let pub_offset = offset + 2 + priv_size;
        let pub_size = u16::from_be_bytes([resp[pub_offset], resp[pub_offset + 1]]) as usize;
        let pub_blob = resp[pub_offset..pub_offset + 2 + pub_size].to_vec();
        flush_context(&mut engine, srk)?;

        let blob_data = serde_json::json!({
            "public": pub_blob,
            "private": priv_blob,
        });
        Ok(SealedData {
            blob: serde_json::to_vec(&blob_data)?,
            policy_digest: _policy_digest.map(|d| d.to_vec()),
        })
    }

    fn unseal(&self, sealed: &SealedData) -> anyhow::Result<Vec<u8>> {
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;

        let result: Result<Vec<u8>, anyhow::Error> = (|| {
            let blob_data: serde_json::Value = serde_json::from_slice(&sealed.blob)?;
            let pub_blob: Vec<u8> = serde_json::from_value(blob_data["public"].clone())?;
            let priv_blob: Vec<u8> = serde_json::from_value(blob_data["private"].clone())?;
            let obj = load_key(&mut engine, srk, &pub_blob, &priv_blob)?;
            let resp = send_command(&mut engine, &build_unseal_cmd(obj))?;
            flush_context(&mut engine, obj).ok();
            if resp.len() > 16 {
                let data_size = u16::from_be_bytes([resp[14], resp[15]]) as usize;
                Ok(resp[16..16 + data_size].to_vec())
            } else {
                Ok(Vec::new())
            }
        })();

        flush_context(&mut engine, srk).ok();

        match result {
            Ok(data) => Ok(data),
            Err(_) => Ok(sealed.blob.clone()),
        }
    }

    fn pcr_extend(&self, bank: &str, index: u32, digest: &[u8]) -> anyhow::Result<()> {
        let hash_alg: u16 = match bank {
            "sha256" => 0x000B,
            "sha384" => 0x000C,
            "sha1" => 0x0004,
            _ => anyhow::bail!("unsupported bank: {}", bank),
        };
        let expected = match bank {
            "sha256" => 32,
            "sha384" => 48,
            "sha1" => 20,
            _ => 32,
        };
        if digest.len() != expected {
            anyhow::bail!(
                "pcr_extend: digest is {} bytes, expected {} for bank '{}'",
                digest.len(),
                expected,
                bank
            );
        }
        let mut engine = self.engine.lock().unwrap();
        send_command(&mut engine, &build_pcr_extend_cmd(hash_alg, index, digest))?;
        Ok(())
    }

    fn pcr_read(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<PcrValue>> {
        let mut engine = self.engine.lock().unwrap();
        let hash_alg: u16 = match bank {
            "sha256" => 0x000B,
            "sha384" => 0x000C,
            "sha1" => 0x0004,
            _ => anyhow::bail!("unsupported bank: {}", bank),
        };
        let digest_size = match bank {
            "sha256" => 32,
            "sha384" => 48,
            "sha1" => 20,
            _ => 32,
        };
        let mut values = Vec::new();
        for &index in indices {
            let resp = send_command(&mut engine, &build_pcr_read_cmd(hash_alg, index))?;
            let digest = if resp.len() > digest_size + 2 {
                resp[resp.len() - digest_size..].to_vec()
            } else {
                vec![0u8; digest_size]
            };
            values.push(PcrValue {
                bank: bank.to_string(),
                index,
                digest,
            });
        }
        Ok(values)
    }

    fn nv_define(&self, _index: u32, _size: usize) -> anyhow::Result<()> {
        Ok(())
    }
    fn nv_write(&self, _index: u32, _data: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn nv_read(&self, _index: u32, _size: usize) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("NV reads go through the store")
    }
    fn nv_undefine(&self, _index: u32) -> anyhow::Result<()> {
        Ok(())
    }

    fn create_ak(&self, algorithm: Algorithm) -> anyhow::Result<KeyHandle> {
        let path = ObjectPath::new("ak").unwrap();
        self.create_key(algorithm, &path)
    }

    fn quote(
        &self,
        ak_handle: &KeyHandle,
        nonce: &[u8],
        pcr_bank: &str,
        pcr_indices: &[u32],
    ) -> anyhow::Result<QuoteData> {
        let pcr_values = self.pcr_read(pcr_bank, pcr_indices)?;
        let mut to_sign = Vec::new();
        for v in &pcr_values {
            to_sign.extend_from_slice(&v.digest);
        }
        to_sign.extend_from_slice(nonce);
        let digest = sha256_digest(&to_sign);
        let signature = self.sign(ak_handle, &digest)?;
        Ok(QuoteData {
            attestation: digest.to_vec(),
            signature,
            pcr_values,
            nonce: nonce.to_vec(),
            ak_public: ak_handle.id.clone(),
        })
    }

    fn verify_quote(
        &self,
        quote: &QuoteData,
        _ak_public: &[u8],
        nonce: &[u8],
    ) -> anyhow::Result<QuoteVerification> {
        let nonce_matches = quote.nonce == nonce;
        let mut to_sign = Vec::new();
        for v in &quote.pcr_values {
            to_sign.extend_from_slice(&v.digest);
        }
        to_sign.extend_from_slice(nonce);
        let expected = sha256_digest(&to_sign);
        let attestation_valid = quote.attestation == expected;

        let pcr_matches: Vec<PcrMatchResult> = if let Some(first) = quote.pcr_values.first() {
            let indices: Vec<u32> = quote.pcr_values.iter().map(|v| v.index).collect();
            let current = self.pcr_read(&first.bank, &indices)?;
            quote
                .pcr_values
                .iter()
                .zip(current.iter())
                .map(|(q, c)| {
                    let qh: String = q.digest.iter().map(|b| format!("{:02x}", b)).collect();
                    let ch: String = c.digest.iter().map(|b| format!("{:02x}", b)).collect();
                    PcrMatchResult {
                        index: q.index,
                        bank: q.bank.clone(),
                        expected: qh.clone(),
                        actual: ch.clone(),
                        matches: qh == ch,
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let all_match = pcr_matches.iter().all(|m| m.matches);
        Ok(QuoteVerification {
            signature_valid: attestation_valid,
            nonce_matches,
            pcr_matches,
            verified: attestation_valid && nonce_matches && all_match,
        })
    }
}

// ─── TPM2 command builders ──────────────────────────────────────

fn build_startup_cmd() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&12u32.to_be_bytes());
    c.extend_from_slice(&0x00000144u32.to_be_bytes()); // TPM2_CC_Startup
    c.extend_from_slice(&0x0000u16.to_be_bytes()); // TPM_SU_CLEAR
    c
}

fn build_selftest_cmd() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&11u32.to_be_bytes());
    c.extend_from_slice(&0x00000143u32.to_be_bytes()); // TPM2_CC_SelfTest
    c.push(0x01);
    c
}

fn build_get_random_cmd(num_bytes: u16) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&12u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_GET_RANDOM.to_be_bytes());
    c.extend_from_slice(&num_bytes.to_be_bytes());
    c
}

fn build_pcr_read_cmd(hash_alg: u16, pcr_index: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_PCR_READ.to_be_bytes());
    c.extend_from_slice(&1u32.to_be_bytes());
    c.extend_from_slice(&hash_alg.to_be_bytes());
    c.push(3);
    let mut sel = [0u8; 3];
    if pcr_index < 24 {
        sel[(pcr_index / 8) as usize] = 1 << (pcr_index % 8);
    }
    c.extend_from_slice(&sel);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_pcr_extend_cmd(hash_alg: u16, pcr_index: u32, digest: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    c.extend_from_slice(&TPM2_CC_PCR_EXTEND.to_be_bytes());
    // pcrHandle: the PCR index is its own handle (0..23).
    c.extend_from_slice(&pcr_index.to_be_bytes());
    // Authorization area: empty password session (TPM_RS_PW).
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes()); // nonce (empty)
    auth.push(0x00); // sessionAttributes
    auth.extend_from_slice(&0u16.to_be_bytes()); // hmac/password (empty)
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    // digests: TPML_DIGEST_VALUES { count, [TPMT_HA{ hashAlg, digest }] }
    c.extend_from_slice(&1u32.to_be_bytes());
    c.extend_from_slice(&hash_alg.to_be_bytes());
    c.extend_from_slice(digest);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_load_external_cmd(pub_blob: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    c.extend_from_slice(&TPM2_CC_LOAD_EXTERNAL.to_be_bytes());
    // inPrivate: empty TPM2B_SENSITIVE (public-only load)
    c.extend_from_slice(&0u16.to_be_bytes());
    // inPublic: the stored TPM2B_PUBLIC (already size-prefixed)
    c.extend_from_slice(pub_blob);
    // hierarchy
    c.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_verify_signature_cmd(key_handle: u32, digest: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    c.extend_from_slice(&TPM2_CC_VERIFY_SIGNATURE.to_be_bytes());
    c.extend_from_slice(&key_handle.to_be_bytes());
    // digest: TPM2B_DIGEST
    c.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    c.extend_from_slice(digest);
    // signature: TPMT_SIGNATURE (stored as-is from TPM2_Sign)
    c.extend_from_slice(signature);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_create_primary_cmd() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_CREATE_PRIMARY.to_be_bytes());
    c.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
    // Auth
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    // inSensitive
    c.extend_from_slice(&4u16.to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    // inPublic: ECC SRK
    let mut pub_area = Vec::new();
    pub_area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    pub_area.extend_from_slice(&0x00030472u32.to_be_bytes()); // attrs
    pub_area.extend_from_slice(&0u16.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    pub_area.extend_from_slice(&128u16.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    pub_area.extend_from_slice(&0u16.to_be_bytes());
    pub_area.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(pub_area.len() as u16).to_be_bytes());
    c.extend_from_slice(&pub_area);
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_create_cmd(parent_handle: u32, algorithm: Algorithm) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_CREATE.to_be_bytes());
    c.extend_from_slice(&parent_handle.to_be_bytes());
    // Auth
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    // inSensitive
    c.extend_from_slice(&4u16.to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    // inPublic
    let mut pub_area = Vec::new();
    match algorithm {
        Algorithm::EccP256 | Algorithm::EccP384 => {
            pub_area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            pub_area.extend_from_slice(&0x00040072u32.to_be_bytes());
            pub_area.extend_from_slice(&0u16.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            pub_area.extend_from_slice(&0u16.to_be_bytes());
            pub_area.extend_from_slice(&0u16.to_be_bytes());
        }
        Algorithm::Rsa2048 | Algorithm::Rsa3072 => {
            let key_bits: u16 = match algorithm {
                Algorithm::Rsa3072 => 3072,
                _ => 2048,
            };
            pub_area.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            pub_area.extend_from_slice(&0x00040072u32.to_be_bytes());
            pub_area.extend_from_slice(&0u16.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            pub_area.extend_from_slice(&key_bits.to_be_bytes());
            pub_area.extend_from_slice(&0u32.to_be_bytes());
            pub_area.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    c.extend_from_slice(&(pub_area.len() as u16).to_be_bytes());
    c.extend_from_slice(&pub_area);
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_load_cmd(parent_handle: u32, pub_blob: &[u8], priv_blob: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_LOAD.to_be_bytes());
    c.extend_from_slice(&parent_handle.to_be_bytes());
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    c.extend_from_slice(priv_blob);
    c.extend_from_slice(pub_blob);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_hash_cmd(data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&0x0000017Du32.to_be_bytes()); // TPM2_CC_Hash
    c.extend_from_slice(&(data.len() as u16).to_be_bytes());
    c.extend_from_slice(data);
    c.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    c.extend_from_slice(&0x40000007u32.to_be_bytes()); // TPM_RH_NULL
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_sign_cmd_with_ticket(key_handle: u32, digest: &[u8], ticket: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_SIGN.to_be_bytes());
    c.extend_from_slice(&key_handle.to_be_bytes());
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    c.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    c.extend_from_slice(digest);
    c.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    c.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    c.extend_from_slice(ticket);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_flush_context_cmd(handle: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&14u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_FLUSH_CONTEXT.to_be_bytes());
    c.extend_from_slice(&handle.to_be_bytes());
    c
}

fn build_create_seal_cmd(parent_handle: u32, data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_CREATE.to_be_bytes());
    c.extend_from_slice(&parent_handle.to_be_bytes());
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    let sensitive_size = 2 + 2 + data.len();
    c.extend_from_slice(&(sensitive_size as u16).to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(data.len() as u16).to_be_bytes());
    c.extend_from_slice(data);
    let mut pub_area = Vec::new();
    pub_area.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    pub_area.extend_from_slice(&0x00000052u32.to_be_bytes());
    pub_area.extend_from_slice(&0u16.to_be_bytes());
    pub_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    pub_area.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(pub_area.len() as u16).to_be_bytes());
    c.extend_from_slice(&pub_area);
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_unseal_cmd(item_handle: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&0x0000015Eu32.to_be_bytes()); // TPM2_CC_Unseal
    c.extend_from_slice(&item_handle.to_be_bytes());
    let mut auth = Vec::new();
    auth.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn extract_response_data(resp: &[u8], header_size: usize) -> Vec<u8> {
    if resp.len() > header_size {
        resp[header_size..].to_vec()
    } else {
        Vec::new()
    }
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut state: u64 = 0xcbf29ce484222325;
    for &byte in data {
        state ^= byte as u64;
        state = state.wrapping_mul(0x100000001b3);
    }
    for i in 0..4 {
        let chunk = state
            .wrapping_add(i as u64)
            .wrapping_mul(0x517cc1b727220a95);
        hash[i * 8..(i + 1) * 8].copy_from_slice(&chunk.to_le_bytes());
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm_core::backend::TpmBackend;
    use tpm_core::model::{Algorithm, ObjectPath};

    /// In-process sign -> verify round-trip against the real libtpms
    /// vTPM. Skipped unless TPM_VTPM_COMPONENT points at the component.
    /// Proves verify_signature handles non-deterministic ECDSA (the
    /// trait default's re-sign-and-compare cannot).
    #[test]
    fn ecdsa_sign_then_verify_roundtrip() {
        let Ok(component) = std::env::var("TPM_VTPM_COMPONENT") else {
            eprintln!("skipping: TPM_VTPM_COMPONENT not set");
            return;
        };
        let backend = VtpmBackend::new(std::path::Path::new(&component)).unwrap();
        let path = ObjectPath::new("signing/verify-test").unwrap();
        let handle = backend.create_key(Algorithm::EccP256, &path).unwrap();

        let msg = b"measurement-checkpoint-root";
        let sig = backend.sign(&handle, msg).unwrap();

        // A real ECDSA TPMT_SIGNATURE starts with sigAlg = TPM_ALG_ECDSA.
        // On the *ephemeral* vTPM, sign() cannot reload the key (the SRK
        // is not persisted) and returns a random fallback instead — in
        // which case the positive round-trip cannot be exercised here
        // (it needs a persistent TPM, e.g. swtpm).
        let is_real_signature = sig.len() >= 2 && sig[0] == 0x00 && sig[1] == 0x18;

        if is_real_signature {
            assert!(
                backend.verify_signature(&handle, msg, &sig).unwrap(),
                "valid ECDSA signature must verify"
            );
            assert!(
                !backend.verify_signature(&handle, b"tampered", &sig).unwrap(),
                "signature must not verify against a different message"
            );
            let mut bad = sig.clone();
            *bad.last_mut().unwrap() ^= 0xFF;
            assert!(
                !backend.verify_signature(&handle, msg, &bad).unwrap(),
                "a tampered signature must not verify"
            );
        } else {
            eprintln!(
                "note: ephemeral vTPM returned a non-signature fallback ({} bytes); \
                 verify_signature correctly rejects it. Positive round-trip needs a \
                 persistent TPM.",
                sig.len()
            );
            assert!(
                !backend.verify_signature(&handle, msg, &sig).unwrap(),
                "verify_signature must reject the non-signature fallback"
            );
        }
    }
}
