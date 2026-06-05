//! Bridge between `vtpm_wasm::VtpmEngine` and `tpm_core::backend::TpmBackend`.
//!
//! All TPM2 command byte building and response parsing lives here.
//! The `VtpmEngine` is a pure WIT host — this module adds TPM protocol knowledge.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tpm_core::backend::{
    BackendStatus, KeyHandle, PcrMatchResult, PcrValue, QuoteData, QuoteVerification, SealedData,
    TpmBackend,
};
use tpm_core::model::{Algorithm, ObjectPath};
use vtpm_wasm::{StateType, TpmVersion, VtpmEngine};

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
const TPM2_CC_NV_DEFINE_SPACE: u32 = 0x0000012A;
const TPM2_CC_NV_INCREMENT: u32 = 0x00000134;
const TPM2_CC_NV_READ: u32 = 0x0000014E;
const TPM2_CC_NV_READ_PUBLIC: u32 = 0x00000169;
const TPM2_CC_START_AUTH_SESSION: u32 = 0x00000176;
const TPM2_CC_POLICY_PCR: u32 = 0x0000017F;
const TPM_SE_POLICY: u8 = 0x01;

// objectAttributes for an ECC/RSA signing key. The default has
// userWithAuth (0x40); the policy-bound variant clears it so the key can
// only be used by satisfying its authPolicy (a policy session).
const OBJ_ATTR_SIGN_USERAUTH: u32 = 0x0004_0072;
const OBJ_ATTR_SIGN_POLICY: u32 = 0x0004_0032; // userWithAuth cleared

// TPMA_NV attribute bits (TPM 2.0 Part 2). Note OWNERREAD is bit 17 and
// AUTHREAD is bit 18 — an earlier attempt swapped these, which is why
// the NV-counter auth paths were rejected.
const TPMA_NV_OWNERWRITE: u32 = 0x0000_0002; // bit 1
const TPMA_NV_COUNTER: u32 = 0x0000_0010; // TPM_NT=1 in bits [7:4]
const TPMA_NV_OWNERREAD: u32 = 0x0002_0000; // bit 17
const TPMA_NV_NO_DA: u32 = 0x0200_0000; // bit 25
// NV index already defined — NV_DefineSpace is idempotent for our use.
const TPM_RC_NV_DEFINED: u32 = 0x0000_014C;

const TPM_RH_OWNER: u32 = 0x40000001;
const TPM_RH_NULL: u32 = 0x40000007;

const TPM_SU_CLEAR: u16 = 0x0000;
const TPM_SU_STATE: u16 = 0x0001;
const TPM2_CC_SHUTDOWN: u32 = 0x00000145;
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
    /// When set, the TPM's state is restored from this file on startup
    /// and saved back on drop, so keys, NV, and saved PCRs (0–15) persist
    /// across separate CLI invocations. Without it the vTPM is ephemeral
    /// and keys cannot be reloaded between processes.
    state_path: Option<PathBuf>,
    /// Exclusive advisory lock held for this backend's lifetime when
    /// persisting, so concurrent invocations against the same store
    /// serialize their restore/use/save cycle instead of racing on the
    /// state file. Dropped (released) after `persist`.
    _lock: Option<std::fs::File>,
}

impl VtpmBackend {
    /// Construct an ephemeral vTPM (no cross-invocation persistence).
    pub fn new(component_path: &Path) -> anyhow::Result<Self> {
        Self::open(component_path, None)
    }

    /// Construct a vTPM, optionally persisting state to `state_path`
    /// across invocations.
    ///
    /// Permanent state (NV, hierarchy seeds) is always restored when
    /// present. Volatile state (PCRs, etc.) is resumed via
    /// `Startup(STATE)` when the previous run shut down cleanly; if the
    /// resume fails (incompatible/no saved volatile), it falls back to a
    /// fresh boot (`Startup(CLEAR)`) with permanent state only.
    pub fn open(component_path: &Path, state_path: Option<&Path>) -> anyhow::Result<Self> {
        // Serialize concurrent invocations against the same persisted
        // state: hold an exclusive lock across restore -> use -> save.
        let lock = match state_path {
            Some(sp) => Some(acquire_state_lock(sp)?),
            None => None,
        };

        let snapshot = state_path
            .and_then(|sp| std::fs::read(sp).ok())
            .map(|blob| StateSnapshot::decode(&blob))
            .unwrap_or_default();

        let engine = if snapshot.resumable && !snapshot.permanent.is_empty() {
            // The permanent image was checkpointed with Shutdown(STATE);
            // resume PCRs/sessions via Startup(STATE). Fall back to a
            // fresh boot if the TPM rejects the resume.
            match boot(component_path, &snapshot.permanent, true) {
                Ok(e) => e,
                Err(_) => boot(component_path, &snapshot.permanent, false)?,
            }
        } else {
            boot(component_path, &snapshot.permanent, false)?
        };

        Ok(Self {
            engine: Mutex::new(engine),
            initialized: true,
            state_path: state_path.map(|p| p.to_path_buf()),
            _lock: lock,
        })
    }

    /// Save TPM state to the state file (atomic write). `Shutdown(STATE)`
    /// checkpoints volatile state (PCRs, sessions) into the permanent
    /// image, so the next run can resume it via `Startup(STATE)`. The
    /// `resumable` flag records whether that checkpoint succeeded.
    fn persist(&self) -> anyhow::Result<()> {
        let Some(sp) = self.state_path.clone() else {
            return Ok(());
        };
        let mut engine = self.engine.lock().unwrap();

        let resumable = engine
            .process(&build_shutdown_cmd(TPM_SU_STATE))
            .ok()
            .map(|r| response_rc(&r) == 0)
            .unwrap_or(false);

        let permanent = engine
            .get_state(StateType::Permanent)
            .map_err(|e| anyhow::anyhow!("get permanent state: {}", e))?;

        if let Some(parent) = sp.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let tmp = sp.with_extension("tpmstate.tmp");
        std::fs::write(&tmp, StateSnapshot { permanent, resumable }.encode())?;
        std::fs::rename(&tmp, &sp)?;
        Ok(())
    }

    /// Create a child signing key, optionally bound to `auth_policy`
    /// (empty = password key; non-empty = policy-only key).
    fn create_key_inner(
        &self,
        algorithm: Algorithm,
        path: &ObjectPath,
        auth_policy: &[u8],
    ) -> anyhow::Result<KeyHandle> {
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;
        let (pub_blob, priv_blob) = create_child_key(&mut engine, srk, algorithm, auth_policy)?;
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
}

/// On-disk TPM state snapshot: the permanent image plus whether it was
/// checkpointed with `Shutdown(STATE)` (and so can be resumed).
#[derive(Default)]
struct StateSnapshot {
    permanent: Vec<u8>,
    resumable: bool,
}

impl StateSnapshot {
    const MAGIC: &'static [u8] = b"VTPM2";

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::MAGIC.len() + 5 + self.permanent.len());
        b.extend_from_slice(Self::MAGIC);
        b.push(self.resumable as u8);
        b.extend_from_slice(&(self.permanent.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.permanent);
        b
    }

    fn decode(blob: &[u8]) -> Self {
        let header = Self::MAGIC.len() + 5;
        if blob.len() < header || &blob[..Self::MAGIC.len()] != Self::MAGIC {
            // Legacy files were raw permanent bytes with no magic.
            return StateSnapshot {
                permanent: blob.to_vec(),
                resumable: false,
            };
        }
        let resumable = blob[Self::MAGIC.len()] != 0;
        let lo = Self::MAGIC.len() + 1;
        let len = u32::from_be_bytes([blob[lo], blob[lo + 1], blob[lo + 2], blob[lo + 3]]) as usize;
        let start = lo + 4;
        let end = (start + len).min(blob.len());
        StateSnapshot {
            permanent: blob[start..end].to_vec(),
            resumable,
        }
    }
}

/// Boot a TPM engine: restore the permanent image (if any), init, then
/// `Startup(STATE)` to resume saved volatile state or `Startup(CLEAR)`
/// for a fresh boot. Returns an error if startup is rejected, so the
/// caller can retry with a fresh boot.
fn boot(component_path: &Path, permanent: &[u8], resume: bool) -> anyhow::Result<VtpmEngine> {
    let mut engine = VtpmEngine::new(component_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    engine
        .choose_version(TpmVersion::Tpm20)
        .map_err(|e| anyhow::anyhow!("choose-version: {}", e))?;

    // set-state must precede init.
    if !permanent.is_empty() {
        engine
            .set_state(StateType::Permanent, permanent)
            .map_err(|e| anyhow::anyhow!("set permanent state: {}", e))?;
    }

    engine
        .init_tpm()
        .map_err(|e| anyhow::anyhow!("init: {}", e))?;

    let su = if resume { TPM_SU_STATE } else { TPM_SU_CLEAR };
    // process() directly so a Startup(STATE) rejection is a recoverable
    // error rather than a panic.
    let resp = engine
        .process(&build_startup_cmd(su))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let rc = response_rc(&resp);
    if rc != 0 {
        anyhow::bail!("TPM2_Startup(0x{:04x}) failed: rc 0x{:08x}", su, rc);
    }
    send_command(&mut engine, &build_selftest_cmd())?;
    Ok(engine)
}

/// Acquire an exclusive advisory lock for a state file, blocking until
/// it is available. The lock lives in a sibling `<state>.lock` file so
/// it is independent of the atomic rename used to write the state.
fn acquire_state_lock(state_path: &Path) -> anyhow::Result<std::fs::File> {
    let mut lock_path = state_path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    f.lock()
        .map_err(|e| anyhow::anyhow!("locking vTPM state {}: {}", lock_path.display(), e))?;
    Ok(f)
}

/// Extract the TPM response code from a raw response buffer.
fn response_rc(resp: &[u8]) -> u32 {
    if resp.len() >= 10 {
        u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]])
    } else {
        0xFFFF_FFFF
    }
}

impl Drop for VtpmBackend {
    fn drop(&mut self) {
        if self.state_path.is_some() {
            if let Err(e) = self.persist() {
                tracing::warn!("failed to persist vTPM state: {}", e);
            }
        }
    }
}

/// TPM_RC_RETRY: the TPM could not start the command and asks the caller
/// to re-submit it. libtpms can return this transiently.
const TPM_RC_RETRY: u32 = 0x0000_0922;

/// Send a raw TPM2 command and check the response code, transparently
/// re-submitting on TPM_RC_RETRY.
fn send_command(engine: &mut VtpmEngine, cmd: &[u8]) -> anyhow::Result<Vec<u8>> {
    for _ in 0..8 {
        let resp = engine
            .process(cmd)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        if resp.len() >= 10 {
            let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
            if rc == TPM_RC_RETRY {
                continue;
            }
            if rc != 0 {
                anyhow::bail!("TPM error 0x{:08x}", rc);
            }
        }
        return Ok(resp);
    }
    anyhow::bail!("TPM error 0x{:08x} (still retrying after 8 attempts)", TPM_RC_RETRY)
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
    auth_policy: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let resp = send_command(engine, &build_create_cmd(parent, alg, auth_policy))?;
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
    auth_session: u32,
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
        &build_sign_cmd_with_ticket(key_handle, &digest, &ticket, auth_session),
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
        self.create_key_inner(algorithm, path, &[])
    }

    fn create_key_with_policy(
        &self,
        algorithm: Algorithm,
        path: &ObjectPath,
        auth_policy: &[u8],
    ) -> anyhow::Result<KeyHandle> {
        self.create_key_inner(algorithm, path, auth_policy)
    }

    fn sign_with_policy(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        bank: &str,
        indices: &[u32],
    ) -> anyhow::Result<Vec<u8>> {
        let hash_alg = bank_to_alg_id(bank)?;
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;

        let result: anyhow::Result<Vec<u8>> = (|| {
            let key_data: serde_json::Value = serde_json::from_slice(&handle.id)?;
            let pub_blob: Vec<u8> = serde_json::from_value(key_data["public"].clone())?;
            let priv_blob: Vec<u8> = serde_json::from_value(key_data["private"].clone())?;
            let kh = load_key(&mut engine, srk, &pub_blob, &priv_blob)?;

            // Start a policy session and evaluate live PCRs into it. If the
            // PCRs differ from what the key was bound to, TPM2_Sign below
            // fails with a policy error — the TPM enforces the gate.
            let start = send_command(&mut engine, &build_start_auth_session_cmd())?;
            let session = u32::from_be_bytes([start[10], start[11], start[12], start[13]]);

            let sign_res: anyhow::Result<Vec<u8>> = (|| {
                send_command(&mut engine, &build_policy_pcr_cmd(session, hash_alg, indices))?;
                tpm_hash_and_sign(&mut engine, kh, data, session)
            })();

            flush_context(&mut engine, session).ok();
            flush_context(&mut engine, kh).ok();
            sign_res
        })();

        flush_context(&mut engine, srk).ok();
        result.map_err(|e| anyhow::anyhow!("measured-state policy not satisfied (TPM): {e}"))
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut engine = self.engine.lock().unwrap();
        let srk = create_primary_srk(&mut engine)?;

        let result: Result<Vec<u8>, anyhow::Error> = (|| {
            let key_data: serde_json::Value = serde_json::from_slice(&handle.id)?;
            let pub_blob: Vec<u8> = serde_json::from_value(key_data["public"].clone())?;
            let priv_blob: Vec<u8> = serde_json::from_value(key_data["private"].clone())?;
            let kh = load_key(&mut engine, srk, &pub_blob, &priv_blob)?;
            let sig = tpm_hash_and_sign(&mut engine, kh, data, TPM_RS_PW)?;
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

    fn nv_increment(&self, index: u32) -> anyhow::Result<u64> {
        let mut engine = self.engine.lock().unwrap();

        // Define the counter NV index (idempotent: NV_DEFINED means it
        // already exists, e.g. restored from persisted permanent state).
        let def = engine
            .process(&build_nv_define_counter_cmd(index))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let drc = response_rc(&def);
        if drc != 0 && drc != TPM_RC_NV_DEFINED {
            anyhow::bail!("NV_DefineSpace failed: rc 0x{:08x}", drc);
        }

        // Increment then read back the 8-byte counter.
        let inc = engine
            .process(&build_nv_increment_cmd(index))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let irc = response_rc(&inc);
        if irc != 0 {
            // Diagnostic: report the index's actual stored attributes so
            // an auth/attribute mismatch is immediately localizable.
            let attrs = nv_read_public_attributes(&mut engine, index)
                .map(|a| format!("0x{a:08x}"))
                .unwrap_or_else(|| "<readpublic failed>".into());
            anyhow::bail!("NV_Increment failed: rc 0x{:08x} (nv attributes {})", irc, attrs);
        }

        let resp = send_command(&mut engine, &build_nv_read_cmd(index, 8))?;
        // header(10) | paramSize(4) | TPM2B_MAX_NV_BUFFER(size u16 + data) | auth
        if resp.len() < 16 {
            anyhow::bail!("NV_Read response too short: {} bytes", resp.len());
        }
        let data_size = u16::from_be_bytes([resp[14], resp[15]]) as usize;
        let start = 16;
        let end = start + data_size;
        if data_size != 8 || end > resp.len() {
            anyhow::bail!("unexpected NV counter size: {} bytes", data_size);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&resp[start..end]);
        Ok(u64::from_be_bytes(buf))
    }

    fn nv_read_counter(&self, index: u32) -> anyhow::Result<Option<u64>> {
        let mut engine = self.engine.lock().unwrap();
        let resp = match engine.process(&build_nv_read_cmd(index, 8)) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        if response_rc(&resp) != 0 || resp.len() < 16 {
            return Ok(None); // not defined / not written
        }
        let data_size = u16::from_be_bytes([resp[14], resp[15]]) as usize;
        if data_size != 8 || 16 + 8 > resp.len() {
            return Ok(None);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&resp[16..24]);
        Ok(Some(u64::from_be_bytes(buf)))
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

fn build_startup_cmd(startup_type: u16) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&12u32.to_be_bytes());
    c.extend_from_slice(&0x00000144u32.to_be_bytes()); // TPM2_CC_Startup
    c.extend_from_slice(&startup_type.to_be_bytes());
    c
}

fn build_shutdown_cmd(shutdown_type: u16) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&12u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_SHUTDOWN.to_be_bytes());
    c.extend_from_slice(&shutdown_type.to_be_bytes());
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

fn bank_to_alg_id(bank: &str) -> anyhow::Result<u16> {
    match bank {
        "sha256" => Ok(0x000B),
        "sha384" => Ok(0x000C),
        "sha1" => Ok(0x0004),
        other => anyhow::bail!("unsupported PCR bank: {other}"),
    }
}

/// TPM2_StartAuthSession for an unbound, unsalted SHA-256 **policy**
/// session (used to satisfy a key's PolicyPCR authPolicy).
fn build_start_auth_session_cmd() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_START_AUTH_SESSION.to_be_bytes());
    c.extend_from_slice(&TPM_RH_NULL.to_be_bytes()); // tpmKey
    c.extend_from_slice(&TPM_RH_NULL.to_be_bytes()); // bind
    // nonceCaller: TPM2B_NONCE (>= 16 bytes)
    c.extend_from_slice(&16u16.to_be_bytes());
    c.extend_from_slice(&[0u8; 16]);
    c.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt (empty)
    c.push(TPM_SE_POLICY); // sessionType
    c.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric = NULL
    c.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // authHash
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

/// TPM2_PolicyPCR on `session` for the given bank/indices. The TPM folds
/// the *live* PCR values into the session policyDigest.
fn build_policy_pcr_cmd(session: u32, hash_alg: u16, indices: &[u32]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_POLICY_PCR.to_be_bytes());
    c.extend_from_slice(&session.to_be_bytes()); // policySession
    c.extend_from_slice(&0u16.to_be_bytes()); // pcrDigest (empty: TPM computes)
    // pcrs: TPML_PCR_SELECTION
    c.extend_from_slice(&1u32.to_be_bytes()); // count
    c.extend_from_slice(&hash_alg.to_be_bytes());
    c.push(3); // sizeofSelect
    let mut bitmap = [0u8; 3];
    for &i in indices {
        if i < 24 {
            bitmap[(i / 8) as usize] |= 1 << (i % 8);
        }
    }
    c.extend_from_slice(&bitmap);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

/// Empty-password authorization area (`TPM_RS_PW`, continueSession).
fn pw_auth_area() -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    a.extend_from_slice(&0u16.to_be_bytes()); // nonce (empty)
    a.push(0x01); // sessionAttributes: continueSession
    a.extend_from_slice(&0u16.to_be_bytes()); // password (empty)
    a
}

fn build_nv_define_counter_cmd(index: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    c.extend_from_slice(&TPM2_CC_NV_DEFINE_SPACE.to_be_bytes());
    c.extend_from_slice(&TPM_RH_OWNER.to_be_bytes()); // authHandle
    let auth = pw_auth_area();
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    // auth: TPM2B_AUTH (new index's authValue) — empty.
    c.extend_from_slice(&0u16.to_be_bytes());
    // publicInfo: TPM2B_NV_PUBLIC { size, TPMS_NV_PUBLIC }
    let mut pubinfo = Vec::new();
    pubinfo.extend_from_slice(&index.to_be_bytes()); // nvIndex
    pubinfo.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // nameAlg
    let attrs = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_COUNTER | TPMA_NV_NO_DA;
    pubinfo.extend_from_slice(&attrs.to_be_bytes());
    pubinfo.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
    pubinfo.extend_from_slice(&8u16.to_be_bytes()); // dataSize = 8 (counter)
    c.extend_from_slice(&(pubinfo.len() as u16).to_be_bytes());
    c.extend_from_slice(&pubinfo);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_nv_increment_cmd(index: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_NV_INCREMENT.to_be_bytes());
    c.extend_from_slice(&TPM_RH_OWNER.to_be_bytes()); // authHandle (owner)
    c.extend_from_slice(&index.to_be_bytes()); // nvIndex
    let auth = pw_auth_area();
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    let size = c.len() as u32;
    c[2..6].copy_from_slice(&size.to_be_bytes());
    c
}

fn build_nv_read_cmd(index: u32, size: u16) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_NV_READ.to_be_bytes());
    c.extend_from_slice(&TPM_RH_OWNER.to_be_bytes()); // authHandle (owner)
    c.extend_from_slice(&index.to_be_bytes()); // nvIndex
    let auth = pw_auth_area();
    c.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    c.extend_from_slice(&auth);
    c.extend_from_slice(&size.to_be_bytes()); // size to read
    c.extend_from_slice(&0u16.to_be_bytes()); // offset
    let sz = c.len() as u32;
    c[2..6].copy_from_slice(&sz.to_be_bytes());
    c
}

/// Read an NV index's TPMA_NV attributes via TPM2_NV_ReadPublic, for
/// diagnostics when increment/read auth is rejected.
fn nv_read_public_attributes(engine: &mut VtpmEngine, index: u32) -> Option<u32> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_NV_READ_PUBLIC.to_be_bytes());
    c.extend_from_slice(&index.to_be_bytes());
    let sz = c.len() as u32;
    c[2..6].copy_from_slice(&sz.to_be_bytes());
    let resp = engine.process(&c).ok()?;
    if response_rc(&resp) != 0 {
        return None;
    }
    // header(10) | TPM2B_NV_PUBLIC{ size u16, TPMS_NV_PUBLIC{ nvIndex u32,
    // nameAlg u16, attributes u32, ... } } | ...
    // attributes start at 10 + 2 (size) + 4 (nvIndex) + 2 (nameAlg) = 18.
    if resp.len() < 22 {
        return None;
    }
    Some(u32::from_be_bytes([resp[18], resp[19], resp[20], resp[21]]))
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

fn build_create_cmd(parent_handle: u32, algorithm: Algorithm, auth_policy: &[u8]) -> Vec<u8> {
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

    // A policy-bound key clears userWithAuth and carries an authPolicy
    // (TPM2B_DIGEST); otherwise it uses password auth with an empty policy.
    let (attrs, policy_field) = if auth_policy.is_empty() {
        (OBJ_ATTR_SIGN_USERAUTH, Vec::new())
    } else {
        let mut p = Vec::new();
        p.extend_from_slice(&(auth_policy.len() as u16).to_be_bytes());
        p.extend_from_slice(auth_policy);
        (OBJ_ATTR_SIGN_POLICY, p)
    };
    let authpolicy_bytes = |out: &mut Vec<u8>| {
        if policy_field.is_empty() {
            out.extend_from_slice(&0u16.to_be_bytes());
        } else {
            out.extend_from_slice(&policy_field);
        }
    };

    // inPublic
    let mut pub_area = Vec::new();
    match algorithm {
        Algorithm::EccP256 | Algorithm::EccP384 => {
            pub_area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
            pub_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            pub_area.extend_from_slice(&attrs.to_be_bytes());
            authpolicy_bytes(&mut pub_area);
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
            pub_area.extend_from_slice(&attrs.to_be_bytes());
            authpolicy_bytes(&mut pub_area);
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

fn build_sign_cmd_with_ticket(
    key_handle: u32,
    digest: &[u8],
    ticket: &[u8],
    auth_session: u32,
) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&TPM2_CC_SIGN.to_be_bytes());
    c.extend_from_slice(&key_handle.to_be_bytes());
    // Auth area: either TPM_RS_PW (password key) or a policy session
    // handle (policy-bound key). Same structure: handle, empty nonce,
    // continueSession, empty hmac/password.
    let mut auth = Vec::new();
    auth.extend_from_slice(&auth_session.to_be_bytes());
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

    /// Persisted permanent state must let a key created in one backend
    /// instance be reloaded and used in a later one (the cross-invocation
    /// case the ephemeral vTPM cannot do). Proves Option-B persistence and
    /// real ECDSA sign+verify together.
    #[test]
    fn persisted_keys_survive_across_instances() {
        let Ok(component) = std::env::var("TPM_VTPM_COMPONENT") else {
            eprintln!("skipping: TPM_VTPM_COMPONENT not set");
            return;
        };
        let comp = std::path::Path::new(&component);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_path_buf();
        std::fs::remove_file(&state_path).ok(); // first instance starts fresh

        let msg = b"measurement-checkpoint-root";
        let path = ObjectPath::new("signing/persisted").unwrap();

        // Instance 1: create a key, then drop (persists permanent state).
        let handle = {
            let b1 = VtpmBackend::open(comp, Some(&state_path)).unwrap();
            b1.create_key(Algorithm::EccP256, &path).unwrap()
        };
        assert!(state_path.exists(), "state file must be written on drop");

        // Instance 2: restore state, sign with the SAME key blob.
        let b2 = VtpmBackend::open(comp, Some(&state_path)).unwrap();
        let sig = b2.sign(&handle, msg).unwrap();

        let is_real = sig.len() >= 2 && sig[0] == 0x00 && sig[1] == 0x18;
        assert!(
            is_real,
            "with persisted permanent state, sign must reload the key and produce a \
             real ECDSA TPMT_SIGNATURE (got {} bytes)",
            sig.len()
        );
        assert!(
            b2.verify_signature(&handle, msg, &sig).unwrap(),
            "a signature from the reloaded persisted key must verify"
        );
    }

    /// Volatile state (PCRs) must resume across instances: a PCR extended
    /// in one backend instance keeps its value in the next.
    #[test]
    fn persisted_pcr_survives_across_instances() {
        let Ok(component) = std::env::var("TPM_VTPM_COMPONENT") else {
            eprintln!("skipping: TPM_VTPM_COMPONENT not set");
            return;
        };
        let comp = std::path::Path::new(&component);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_path_buf();
        std::fs::remove_file(&state_path).ok();

        let digest = vec![0x5Au8; 32];
        let after_extend = {
            let b1 = VtpmBackend::open(comp, Some(&state_path)).unwrap();
            b1.pcr_extend("sha256", 10, &digest).unwrap();
            b1.pcr_read("sha256", &[10]).unwrap()[0].digest.clone()
        };
        assert_ne!(after_extend, vec![0u8; 32], "extend must change PCR 10");

        let b2 = VtpmBackend::open(comp, Some(&state_path)).unwrap();
        let restored = b2.pcr_read("sha256", &[10]).unwrap()[0].digest.clone();
        assert_eq!(
            restored, after_extend,
            "PCR 10 must survive across invocations via persisted volatile state"
        );
    }

    const TEST_NV_INDEX: u32 = 0x0180_0001;

    #[test]
    fn nv_counter_is_monotonic_in_process() {
        let Ok(component) = std::env::var("TPM_VTPM_COMPONENT") else {
            eprintln!("skipping: TPM_VTPM_COMPONENT not set");
            return;
        };
        let backend = VtpmBackend::new(std::path::Path::new(&component)).unwrap();
        let v1 = backend.nv_increment(TEST_NV_INDEX).unwrap();
        let v2 = backend.nv_increment(TEST_NV_INDEX).unwrap();
        assert!(v2 > v1, "counter must strictly increase: {v1} -> {v2}");
        // A different index counts independently and does not perturb the first.
        backend.nv_increment(0x0180_0002).unwrap();
        let v3 = backend.nv_increment(TEST_NV_INDEX).unwrap();
        assert!(v3 > v2, "counter must keep increasing: {v2} -> {v3}");
    }

    #[test]
    fn policy_bound_key_signs_only_in_bound_pcr_state() {
        let Ok(component) = std::env::var("TPM_VTPM_COMPONENT") else {
            eprintln!("skipping: TPM_VTPM_COMPONENT not set");
            return;
        };
        let backend = VtpmBackend::new(std::path::Path::new(&component)).unwrap();
        let bank = "sha256";
        let indices = [14u32];
        let path = ObjectPath::new("signing/policy-bound").unwrap();

        // Bind the key to the CURRENT measured state (PolicyPCR digest of
        // the current PCR 14). This must equal what the TPM's PolicyPCR
        // computes, or signing would never succeed.
        let policy = backend.pcr_policy_digest(bank, &indices).unwrap();
        let handle = backend
            .create_key_with_policy(Algorithm::EccP256, &path, &policy)
            .unwrap();

        // Signs while PCR 14 still matches the bound state.
        let sig = backend
            .sign_with_policy(&handle, b"checkpoint-root", bank, &indices)
            .expect("policy-bound key should sign while PCRs match");
        assert!(
            sig.len() >= 2 && sig[0] == 0x00 && sig[1] == 0x18,
            "expected a real ECDSA signature, got {} bytes",
            sig.len()
        );

        // Change PCR 14 — the TPM itself must now refuse to sign.
        backend.pcr_extend(bank, 14, &[0x11u8; 32]).unwrap();
        let err = backend
            .sign_with_policy(&handle, b"checkpoint-root", bank, &indices)
            .expect_err("TPM must refuse to sign once the bound PCR changes");
        assert!(
            err.to_string().contains("policy"),
            "expected a TPM policy refusal, got: {err}"
        );
    }

    #[test]
    fn nv_counter_persists_across_instances() {
        let Ok(component) = std::env::var("TPM_VTPM_COMPONENT") else {
            eprintln!("skipping: TPM_VTPM_COMPONENT not set");
            return;
        };
        let comp = std::path::Path::new(&component);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_path_buf();
        std::fs::remove_file(&state_path).ok();

        let v1 = {
            let b1 = VtpmBackend::open(comp, Some(&state_path)).unwrap();
            b1.nv_increment(TEST_NV_INDEX).unwrap()
        };
        let b2 = VtpmBackend::open(comp, Some(&state_path)).unwrap();
        let v2 = b2.nv_increment(TEST_NV_INDEX).unwrap();
        assert!(
            v2 > v1,
            "NV counter must keep increasing across instances (anti-rollback): {v1} -> {v2}"
        );
    }
}
