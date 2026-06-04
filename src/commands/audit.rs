//! `tpm audit …` — secure log CLI surface.
//!
//! Phase 1 commands: append, show, head, chain verify. Phase 2
//! adds segment + inclusion-proof subcommands; Phase 3 adds
//! checkpoint signing and verification; Phase 4 adds witness
//! publication; Phase 5 adds encrypted reads.
//!
//! All commands construct a dedicated [`NativeSecureLog`] over the
//! same SQLite database as the rest of the workspace. The secure log
//! never shares a [`Store`] instance with other subsystems — see the
//! doc comment on `NativeSecureLog` for rationale.

use std::io::Read;
use std::path::Path;

use serde::Serialize;

use tpm_core::backend::TpmBackend;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::secure_log::{
    crypto::SecretKey, hash::hex, verify_inclusion_proof, witness::WitnessSubmission,
    CborEncoder, EntryFields, InclusionProof, NativeSecureLog, SecureLog, SegmentInfo,
};
use tpm_core::secure_log_signer::TpmCheckpointSigner;
use tpm_core::store::Store;
use secure_log_sqlite::SqliteSecureLogStore;

/// Open a fresh secure-log instance backed by the given store path.
/// The session id is freshly generated each invocation so CLI calls
/// are distinguishable in forensic review. The head file path is
/// derived from the store path so anti-rollback state is tracked
/// automatically for every CLI invocation that signs or verifies.
///
/// Plaintext variant: used by commands that never touch encrypted
/// payloads (append/show without --encrypt/--decrypt, chain verify,
/// segments, prove, publish, rollback). These still need to work
/// on stores that contain encrypted entries — chain verification
/// operates on stored bytes and does not care about decryption.
fn open_log(store_path: &Path) -> anyhow::Result<NativeSecureLog> {
    let store = SqliteSecureLogStore::open(store_path)?;
    let head_path = tpm_core::secure_log::witness::HeadFile::path_for_store(store_path);
    let mut log = NativeSecureLog::new(Box::new(store), Box::new(CborEncoder::new()))
        .with_head_file(head_path);
    // Best effort: only load the master key if it's in the
    // plaintext format. Sealed keys require a backend, which
    // this variant does not have.
    if let Ok(Some(key)) = try_load_master_key(store_path) {
        log = log.with_master_key(key);
    }
    Ok(log)
}

/// Same as [`open_log`] but uses `backend` to unseal a
/// TPM-protected audit key when present. Required for
/// `append --encrypt`, `show --decrypt`, and any other command
/// that needs envelope encryption to work.
fn open_log_with_backend(
    store_path: &Path,
    backend: &dyn TpmBackend,
) -> anyhow::Result<NativeSecureLog> {
    let store = SqliteSecureLogStore::open(store_path)?;
    let head_path = tpm_core::secure_log::witness::HeadFile::path_for_store(store_path);
    let mut log = NativeSecureLog::new(Box::new(store), Box::new(CborEncoder::new()))
        .with_head_file(head_path);
    if let Some(key) = try_load_master_key_with_backend(store_path, backend)? {
        log = log.with_master_key(key);
    }
    Ok(log)
}

/// Standard path for the master KEK, alongside the store database.
pub fn audit_key_path_for_store(store_path: &Path) -> std::path::PathBuf {
    let mut p = store_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tpm.db".into());
    p.set_file_name(format!("{}.auditkey", stem));
    p
}

fn try_load_master_key(store_path: &Path) -> anyhow::Result<Option<SecretKey>> {
    let path = audit_key_path_for_store(store_path);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    // Format auto-detection:
    //   - 32 raw bytes            → unsealed legacy format
    //   - JSON { sealed_hex: .. } → sealed under a TPM key
    // Sealed format is only parseable when we have a backend to
    // unseal with; CLI callers that need encryption must pass the
    // backend through `try_load_master_key_with_backend`.
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(Some(SecretKey::new(arr)));
    }
    // Not 32 raw bytes → probably sealed. Parse the envelope so
    // the caller can unseal via backend.
    match serde_json::from_slice::<SealedKeyFile>(&bytes) {
        Ok(_) => Err(anyhow::anyhow!(
            "audit key at {} is sealed under a TPM key; \
             open it with a backend-aware caller",
            path.display()
        )),
        Err(_) => Err(anyhow::anyhow!(
            "audit key file has wrong length: expected 32 bytes, got {}",
            bytes.len()
        )),
    }
}

/// Load the master KEK, unsealing it via the TPM backend if the
/// file is in sealed format. Falls back to plaintext load for
/// legacy unsealed files. Used by every CLI command that touches
/// encrypted payloads.
pub fn try_load_master_key_with_backend(
    store_path: &Path,
    backend: &dyn TpmBackend,
) -> anyhow::Result<Option<SecretKey>> {
    let path = audit_key_path_for_store(store_path);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(Some(SecretKey::new(arr)));
    }
    let envelope: SealedKeyFile = serde_json::from_slice(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "audit key at {} is not valid (length {}, parse {})",
            path.display(),
            bytes.len(),
            e
        )
    })?;
    let blob_bytes = hex_to_bytes(&envelope.sealed_hex)?;
    let policy = envelope
        .policy_digest_hex
        .as_deref()
        .map(hex_to_bytes)
        .transpose()?;
    let sealed = tpm_core::backend::SealedData {
        blob: blob_bytes,
        policy_digest: policy,
    };
    let plaintext = backend.unseal(&sealed)?;
    if plaintext.len() != 32 {
        anyhow::bail!(
            "unsealed audit key has wrong length: expected 32 bytes, got {}",
            plaintext.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&plaintext);
    Ok(Some(SecretKey::new(arr)))
}

/// On-disk envelope for a sealed audit key. The `sealed_hex` field
/// is a TPM-sealed blob whose plaintext is the 32-byte KEK.
#[derive(serde::Serialize, serde::Deserialize)]
struct SealedKeyFile {
    version: u32,
    sealed_hex: String,
    #[serde(default)]
    policy_digest_hex: Option<String>,
}

fn hex_to_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("odd-length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{}", e)))
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn key_init(
    store_path: &Path,
    backend: &dyn TpmBackend,
    out_override: Option<&Path>,
    plaintext: bool,
) -> anyhow::Result<()> {
    let path = match out_override {
        Some(p) => p.to_path_buf(),
        None => audit_key_path_for_store(store_path),
    };
    if path.exists() {
        anyhow::bail!(
            "refusing to overwrite existing audit key at {}",
            path.display()
        );
    }
    let key = SecretKey::generate();

    if plaintext {
        std::fs::write(&path, key.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        println!("audit key written to: {} (plaintext, 0600)", path.display());
    } else {
        // Seal under a TPM-protected key. The resulting envelope
        // can only be unsealed by the same TPM (or its equivalent
        // mock backend), so copying the file off-host does not
        // disclose the master key.
        let sealed = backend
            .seal(key.as_bytes(), None)
            .map_err(|e| anyhow::anyhow!("backend seal failed: {}", e))?;
        let envelope = SealedKeyFile {
            version: 1,
            sealed_hex: bytes_to_hex(&sealed.blob),
            policy_digest_hex: sealed.policy_digest.as_deref().map(bytes_to_hex),
        };
        let json = serde_json::to_vec_pretty(&envelope)?;
        std::fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        println!("audit key written to: {} (sealed, 0600)", path.display());
    }

    println!(
        "Keep this file protected. Loss of the key makes protected payloads\n\
         unrecoverable; leak of a plaintext key exposes all historical payloads\n\
         (a sealed key is bound to the TPM and cannot be used elsewhere)."
    );
    Ok(())
}

// -- streams (multi-stream support) --

/// Tier enforcement: decide whether an append to this stream must
/// be encrypted. Returns the effective `encrypt` bool after applying
/// stream policy and the user's requested flag.
///
/// - `public`            : `--encrypt` is opt-in.
/// - `protected`         : payload is always encrypted (caller flag
///                          is ignored if false).
/// - `highly-restricted` : same as protected. Metadata minimization
///                          is the caller's responsibility for now.
fn effective_encryption(
    store: &Store,
    stream: &str,
    user_encrypt: bool,
) -> anyhow::Result<bool> {
    let Some(row) = store.secure_log_stream_get(stream)? else {
        // Unknown stream: treat as public, but surface the fact so
        // users can explicitly create it.
        eprintln!(
            "warning: stream '{}' is not declared; treating as public. Create it with `tpm audit streams create {}`.",
            stream, stream
        );
        return Ok(user_encrypt);
    };
    match row.tier.as_str() {
        "public" => Ok(user_encrypt),
        "protected" | "highly-restricted" => {
            if !user_encrypt {
                // Auto-promote. Tell the user so they know why.
                eprintln!(
                    "note: stream '{}' is {} — payload will be encrypted even without --encrypt",
                    stream, row.tier
                );
            }
            Ok(true)
        }
        other => {
            anyhow::bail!(
                "stream '{}' has unknown tier '{}'",
                stream,
                other
            )
        }
    }
}

pub fn streams_list(store_path: &Path, format: OutputFormat) -> anyhow::Result<()> {
    let store = Store::open(store_path)?;
    let rows = store.secure_log_stream_list()?;
    let out = StreamsListOutput {
        streams: rows
            .iter()
            .map(|r| StreamOutput {
                name: r.name.clone(),
                tier: r.tier.clone(),
                description: r.description.clone(),
                created_at: r.created_at_rfc3339.clone(),
                deprecated_at: r.deprecated_at_rfc3339.clone(),
            })
            .collect(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn streams_create(
    store_path: &Path,
    name: &str,
    tier: &str,
    description: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    // Validate tier before touching the store.
    let _: tpm_core::secure_log::crypto::ConfidentialityTier =
        tier.parse().map_err(|e: String| anyhow::anyhow!(e))?;

    let store = Store::open(store_path)?;
    if store.secure_log_stream_get(name)?.is_some() {
        anyhow::bail!("stream already exists: {}", name);
    }
    let row = tpm_core::store::SecureLogStreamRow {
        name: name.to_string(),
        tier: tier.to_string(),
        description: description.map(String::from),
        created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
        deprecated_at_rfc3339: None,
    };
    store.secure_log_stream_upsert(&row)?;
    store.log_action(
        "audit.stream.create",
        Some(name),
        &serde_json::json!({"tier": tier}),
    )?;
    let out = StreamOutput {
        name: row.name,
        tier: row.tier,
        description: row.description,
        created_at: row.created_at_rfc3339,
        deprecated_at: row.deprecated_at_rfc3339,
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn streams_show(
    store_path: &Path,
    name: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let store = Store::open(store_path)?;
    let row = store
        .secure_log_stream_get(name)?
        .ok_or_else(|| anyhow::anyhow!("stream not found: {}", name))?;
    let out = StreamOutput {
        name: row.name,
        tier: row.tier,
        description: row.description,
        created_at: row.created_at_rfc3339,
        deprecated_at: row.deprecated_at_rfc3339,
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn streams_set_tier(
    store_path: &Path,
    name: &str,
    tier: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let _: tpm_core::secure_log::crypto::ConfidentialityTier =
        tier.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let store = Store::open(store_path)?;
    store.secure_log_stream_set_tier(name, tier)?;
    store.log_action(
        "audit.stream.set_tier",
        Some(name),
        &serde_json::json!({"tier": tier}),
    )?;
    streams_show(store_path, name, format)
}

pub fn streams_delete(
    store_path: &Path,
    name: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let store = Store::open(store_path)?;
    if store.secure_log_stream_get(name)?.is_none() {
        anyhow::bail!("stream not found: {}", name);
    }
    let deprecated_at = chrono::Utc::now().to_rfc3339();
    store.secure_log_stream_deprecate(name, &deprecated_at)?;
    store.log_action(
        "audit.stream.deprecate",
        Some(name),
        &serde_json::json!({"deprecated_at": deprecated_at}),
    )?;
    streams_show(store_path, name, format)
}

#[derive(Serialize)]
struct StreamOutput {
    name: String,
    tier: String,
    description: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    deprecated_at: Option<String>,
}

impl TextRenderable for StreamOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("name:        {}\n", self.name));
        out.push_str(&format!("tier:        {}\n", self.tier));
        out.push_str(&format!(
            "description: {}\n",
            self.description.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!("created_at:  {}\n", self.created_at));
        if let Some(dep) = &self.deprecated_at {
            out.push_str(&format!("deprecated:  {}\n", dep));
        }
        out
    }
}

#[derive(Serialize)]
struct StreamsListOutput {
    streams: Vec<StreamOutput>,
}

impl TextRenderable for StreamsListOutput {
    fn render_text(&self) -> String {
        if self.streams.is_empty() {
            return "no streams\n".to_string();
        }
        let mut out = String::new();
        for s in &self.streams {
            let dep_tag = if s.deprecated_at.is_some() {
                " (deprecated)"
            } else {
                ""
            };
            out.push_str(&format!(
                "  {:<20} [{}]{}{}\n",
                s.name,
                s.tier,
                dep_tag,
                s.description
                    .as_deref()
                    .map(|d| format!(" — {}", d))
                    .unwrap_or_default()
            ));
        }
        out
    }
}

pub fn key_show(store_path: &Path) -> anyhow::Result<()> {
    let path = audit_key_path_for_store(store_path);
    println!("audit key path: {}", path.display());
    if !path.exists() {
        println!("  present: no");
        return Ok(());
    }
    let bytes = std::fs::read(&path)?;
    let format = if bytes.len() == 32 {
        "plaintext"
    } else if serde_json::from_slice::<SealedKeyFile>(&bytes).is_ok() {
        "sealed"
    } else {
        "unknown"
    };
    println!("  present: yes");
    println!("  format:  {}", format);
    Ok(())
}

// -- append --

/// Append an entry with raw payload bytes and return the assigned
/// seqno, without printing. Shared core used by `append` and by the
/// `tpm measure` commands (which build structured payloads).
#[allow(clippy::too_many_arguments)]
pub fn append_value(
    store_path: &Path,
    backend: &dyn TpmBackend,
    stream: &str,
    event: &str,
    severity: &str,
    producer: &str,
    payload: &[u8],
    encrypt: bool,
) -> anyhow::Result<u64> {
    let effective_encrypt = {
        let store = Store::open(store_path)?;
        effective_encryption(&store, stream, encrypt)?
    };
    let result = if effective_encrypt {
        let log = open_log_with_backend(store_path, backend)?;
        log.append_encrypted(stream, event, severity, producer, payload)
            .map_err(|e| anyhow::anyhow!("{}", e))?
    } else {
        let log = open_log(store_path)?;
        log.append(stream, event, severity, producer, payload)
            .map_err(|e| anyhow::anyhow!("{}", e))?
    };
    Ok(result.seqno)
}

pub fn append(
    store_path: &Path,
    backend: &dyn TpmBackend,
    stream: &str,
    event: &str,
    severity: &str,
    producer: &str,
    payload_inline: Option<&str>,
    payload_file: Option<&Path>,
    encrypt: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let payload: Vec<u8> = match (payload_inline, payload_file) {
        (Some(s), _) => s.as_bytes().to_vec(),
        (None, Some(p)) if p.as_os_str() == "-" => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
        (None, Some(p)) => std::fs::read(p)?,
        (None, None) => Vec::new(),
    };

    // Apply stream-level tier enforcement before touching the
    // secure log. A protected/highly-restricted stream auto-
    // promotes append→append_encrypted; a public stream honors
    // the user's --encrypt flag.
    let effective_encrypt = {
        let store = Store::open(store_path)?;
        effective_encryption(&store, stream, encrypt)?
    };

    // Only open the backend-aware log when we need encryption;
    // non-encrypted appends don't touch the master KEK and skip
    // any unseal work.
    let result = if effective_encrypt {
        let log = open_log_with_backend(store_path, backend)?;
        log.append_encrypted(stream, event, severity, producer, &payload)
            .map_err(|e| anyhow::anyhow!("{}", e))?
    } else {
        let log = open_log(store_path)?;
        log.append(stream, event, severity, producer, &payload)
            .map_err(|e| anyhow::anyhow!("{}", e))?
    };

    let out = AppendOutput {
        seqno: result.seqno,
        stream: stream.to_string(),
        entry_hash: hex(&result.entry_hash),
        payload_bytes: payload.len(),
        encrypted: effective_encrypt,
    };
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct AppendOutput {
    seqno: u64,
    stream: String,
    entry_hash: String,
    payload_bytes: usize,
    encrypted: bool,
}

impl TextRenderable for AppendOutput {
    fn render_text(&self) -> String {
        format!(
            "appended entry\n  seqno:      {}\n  stream:     {}\n  entry_hash: {}\n  payload:    {} bytes{}\n",
            self.seqno,
            self.stream,
            self.entry_hash,
            self.payload_bytes,
            if self.encrypted { " (encrypted)" } else { "" }
        )
    }
}

// -- show --

pub fn show(
    store_path: &Path,
    backend: &dyn TpmBackend,
    seqno: u64,
    decrypt: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    // When decrypt is requested and the key is sealed we need the
    // backend to unseal. When decrypt is false we never need it.
    let log = if decrypt {
        open_log_with_backend(store_path, backend)?
    } else {
        open_log(store_path)?
    };
    let entry = log.read(seqno).map_err(|e| anyhow::anyhow!("{}", e))?;
    let plaintext = if decrypt {
        Some(
            log.open_payload(seqno)
                .map_err(|e| anyhow::anyhow!("decrypt failed: {}", e))?,
        )
    } else {
        None
    };
    let mut out = EntryOutput::from(&entry);
    if let Some(pt) = plaintext {
        out.payload_plaintext = Some(String::from_utf8_lossy(&pt).into_owned());
    }
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct EntryOutput {
    seqno: u64,
    stream: String,
    session_id: String,
    boot_id: String,
    timestamp: String,
    event_type: String,
    severity: String,
    producer: String,
    payload_encoding: String,
    payload_hex: String,
    prev_entry_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_plaintext: Option<String>,
}

impl From<&EntryFields> for EntryOutput {
    fn from(e: &EntryFields) -> Self {
        let payload_hex: String = e.payload.iter().map(|b| format!("{:02x}", b)).collect();
        let prev_hex: String = e
            .prev_entry_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        Self {
            seqno: e.seqno,
            stream: e.stream_id.clone(),
            session_id: e.session_id.clone(),
            boot_id: e.boot_id.clone(),
            timestamp: e.timestamp_rfc3339.clone(),
            event_type: e.event_type.clone(),
            severity: e.severity.clone(),
            producer: e.producer.clone(),
            payload_encoding: e.payload_encoding.clone(),
            payload_hex,
            prev_entry_hash: prev_hex,
            payload_plaintext: None,
        }
    }
}

impl TextRenderable for EntryOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("seqno:         {}\n", self.seqno));
        out.push_str(&format!("stream:        {}\n", self.stream));
        out.push_str(&format!("session_id:    {}\n", self.session_id));
        out.push_str(&format!("boot_id:       {}\n", self.boot_id));
        out.push_str(&format!("timestamp:     {}\n", self.timestamp));
        out.push_str(&format!("event_type:    {}\n", self.event_type));
        out.push_str(&format!("severity:      {}\n", self.severity));
        out.push_str(&format!("producer:      {}\n", self.producer));
        out.push_str(&format!("encoding:      {}\n", self.payload_encoding));
        out.push_str(&format!("prev_hash:     {}\n", self.prev_entry_hash));
        out.push_str(&format!("payload (hex): {}\n", self.payload_hex));
        if let Some(ref pt) = self.payload_plaintext {
            out.push_str(&format!("plaintext:     {}\n", pt));
        }
        out
    }
}

// -- head --

pub fn head(store_path: &Path, stream: &str, format: OutputFormat) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let head = log.head(stream).map_err(|e| anyhow::anyhow!("{}", e))?;
    let out = HeadOutput {
        stream: stream.to_string(),
        head,
    };
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct HeadOutput {
    stream: String,
    head: Option<u64>,
}

impl TextRenderable for HeadOutput {
    fn render_text(&self) -> String {
        match self.head {
            Some(h) => format!("stream {}: head = {}\n", self.stream, h),
            None => format!("stream {}: empty\n", self.stream),
        }
    }
}

// -- chain verify --

pub fn chain_verify(
    store_path: &Path,
    stream: &str,
    from: u64,
    to: Option<u64>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let to = match to {
        Some(t) => t,
        None => log
            .head(stream)
            .map_err(|e| anyhow::anyhow!("{}", e))?
            .ok_or_else(|| anyhow::anyhow!("stream '{}' is empty", stream))?,
    };

    match log.verify_chain(stream, from, to) {
        Ok(()) => {
            let out = VerifyOutput {
                stream: stream.to_string(),
                from,
                to,
                ok: true,
                error: None,
            };
            println!("{}", render(&out, format));
            Ok(())
        }
        Err(e) => {
            let out = VerifyOutput {
                stream: stream.to_string(),
                from,
                to,
                ok: false,
                error: Some(e.to_string()),
            };
            println!("{}", render(&out, format));
            anyhow::bail!("chain verification failed: {}", e);
        }
    }
}

#[derive(Serialize)]
struct VerifyOutput {
    stream: String,
    from: u64,
    to: u64,
    ok: bool,
    error: Option<String>,
}

impl TextRenderable for VerifyOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "verify chain: stream={} range=[{},{}]\n",
            self.stream, self.from, self.to
        ));
        if self.ok {
            out.push_str("  result: ok (all links verified)\n");
        } else {
            out.push_str("  result: FAILED\n");
            if let Some(ref e) = self.error {
                out.push_str(&format!("  error:  {}\n", e));
            }
        }
        out
    }
}

// -- segments --

pub fn segments_close(
    store_path: &Path,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let seg = log
        .close_segment(stream)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("{}", render(&SegmentOutput::from(&seg), format));
    Ok(())
}

pub fn segments_list(
    store_path: &Path,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let segs = log
        .list_segments(stream)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let out = SegmentListOutput {
        stream: stream.to_string(),
        segments: segs.iter().map(SegmentOutput::from).collect(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn segments_show(
    store_path: &Path,
    segment_id: u64,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let seg = log
        .read_segment(segment_id)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("{}", render(&SegmentOutput::from(&seg), format));
    Ok(())
}

pub fn prove(
    store_path: &Path,
    seqno: u64,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let proof = log
        .inclusion_proof(seqno)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    // Sanity: verify the proof we just built, so the CLI round-trips
    // the proof and catches bugs locally before a verifier sees them.
    verify_inclusion_proof(&proof, &proof.merkle_root)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("{}", render(&ProofOutput::from(&proof), format));
    Ok(())
}

#[derive(Serialize)]
struct SegmentOutput {
    segment_id: u64,
    stream: String,
    seq_start: u64,
    seq_end: u64,
    merkle_root: String,
    last_entry_hash: String,
    prev_checkpoint_hash: String,
    closed_at: String,
    signed: bool,
    signer_identity: Option<String>,
}

impl From<&SegmentInfo> for SegmentOutput {
    fn from(s: &SegmentInfo) -> Self {
        Self {
            segment_id: s.segment_id,
            stream: s.stream_id.clone(),
            seq_start: s.seq_start,
            seq_end: s.seq_end,
            merkle_root: hex(&s.merkle_root),
            last_entry_hash: hex(&s.last_entry_hash),
            prev_checkpoint_hash: hex(&s.prev_checkpoint_hash),
            closed_at: s.closed_at_rfc3339.clone(),
            signed: !s.signature.is_empty(),
            signer_identity: s.signer_identity.clone(),
        }
    }
}

impl TextRenderable for SegmentOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("segment_id:     {}\n", self.segment_id));
        out.push_str(&format!("stream:         {}\n", self.stream));
        out.push_str(&format!(
            "range:          [{}, {}] ({} entries)\n",
            self.seq_start,
            self.seq_end,
            self.seq_end - self.seq_start + 1
        ));
        out.push_str(&format!("merkle_root:    {}\n", self.merkle_root));
        out.push_str(&format!("last_entry:     {}\n", self.last_entry_hash));
        out.push_str(&format!("prev_checkpoint:{}\n", self.prev_checkpoint_hash));
        out.push_str(&format!("closed_at:      {}\n", self.closed_at));
        out.push_str(&format!(
            "signed:         {}\n",
            if self.signed { "yes" } else { "no" }
        ));
        if let Some(ref sid) = self.signer_identity {
            out.push_str(&format!("signer:         {}\n", sid));
        }
        out
    }
}

#[derive(Serialize)]
struct SegmentListOutput {
    stream: String,
    segments: Vec<SegmentOutput>,
}

impl TextRenderable for SegmentListOutput {
    fn render_text(&self) -> String {
        if self.segments.is_empty() {
            return format!("stream {}: no segments\n", self.stream);
        }
        let mut out = format!("stream {}:\n", self.stream);
        for s in &self.segments {
            out.push_str(&format!(
                "  segment {}: seqs [{}, {}] root={}...{} signed={}\n",
                s.segment_id,
                s.seq_start,
                s.seq_end,
                &s.merkle_root[..8],
                &s.merkle_root[s.merkle_root.len() - 8..],
                s.signed
            ));
        }
        out
    }
}

#[derive(Serialize)]
struct ProofOutput {
    seqno: u64,
    segment_id: u64,
    entry_hash: String,
    merkle_root: String,
    path_length: usize,
    path: Vec<ProofStepOutput>,
}

#[derive(Serialize)]
struct ProofStepOutput {
    sibling_hash: String,
    right: bool,
}

impl From<&InclusionProof> for ProofOutput {
    fn from(p: &InclusionProof) -> Self {
        Self {
            seqno: p.seqno,
            segment_id: p.segment_id,
            entry_hash: hex(&p.entry_hash),
            merkle_root: hex(&p.merkle_root),
            path_length: p.path.len(),
            path: p
                .path
                .iter()
                .map(|s| ProofStepOutput {
                    sibling_hash: hex(&s.sibling_hash),
                    right: s.right,
                })
                .collect(),
        }
    }
}

impl TextRenderable for ProofOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "inclusion proof: seqno={} segment={}\n",
            self.seqno, self.segment_id
        ));
        out.push_str(&format!("  entry_hash:   {}\n", self.entry_hash));
        out.push_str(&format!("  merkle_root:  {}\n", self.merkle_root));
        out.push_str(&format!("  path_length:  {}\n", self.path_length));
        for (i, s) in self.path.iter().enumerate() {
            let side = if s.right { "R" } else { "L" };
            out.push_str(&format!(
                "    {}. [{}] {}\n",
                i, side, s.sibling_hash
            ));
        }
        out.push_str("\nproof verified locally.\n");
        out
    }
}

// -- sign / verify --

pub fn sign(
    store_path: &Path,
    backend: &dyn TpmBackend,
    segment_id: u64,
    identity: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    // Identity resolution still needs the citadel Store; secure-log's
    // store doesn't know about the identity tables.
    let id_store = Store::open(store_path)?;
    let signer = TpmCheckpointSigner::new(backend, &id_store);
    let (ckpt_hash, sig) = log
        .sign_segment(&signer, identity, segment_id)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let out = SignOutput {
        segment_id,
        identity: identity.to_string(),
        checkpoint_hash: hex(&ckpt_hash),
        signature_hex: sig.iter().map(|b| format!("{:02x}", b)).collect(),
        signature_bytes: sig.len(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct SignOutput {
    segment_id: u64,
    identity: String,
    checkpoint_hash: String,
    signature_hex: String,
    signature_bytes: usize,
}

impl TextRenderable for SignOutput {
    fn render_text(&self) -> String {
        format!(
            "signed segment\n  segment_id:      {}\n  identity:        {}\n  checkpoint_hash: {}\n  signature:       {} bytes ({})\n",
            self.segment_id,
            self.identity,
            self.checkpoint_hash,
            self.signature_bytes,
            self.signature_hex
        )
    }
}

pub fn verify(
    store_path: &Path,
    backend: &dyn TpmBackend,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let id_store = Store::open(store_path)?;
    let signer = TpmCheckpointSigner::new(backend, &id_store);
    match log.verify_checkpoint_chain(&signer, stream) {
        Ok(count) => {
            let out = ChainVerifyOutput {
                stream: stream.to_string(),
                segments_verified: count,
                ok: true,
                error: None,
            };
            println!("{}", render(&out, format));
            Ok(())
        }
        Err(e) => {
            let out = ChainVerifyOutput {
                stream: stream.to_string(),
                segments_verified: 0,
                ok: false,
                error: Some(e.to_string()),
            };
            println!("{}", render(&out, format));
            anyhow::bail!("checkpoint chain verification failed: {}", e);
        }
    }
}

#[derive(Serialize)]
struct ChainVerifyOutput {
    stream: String,
    segments_verified: usize,
    ok: bool,
    error: Option<String>,
}

impl TextRenderable for ChainVerifyOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("verify checkpoint chain: stream={}\n", self.stream));
        if self.ok {
            out.push_str(&format!(
                "  result: ok ({} segment(s) verified)\n",
                self.segments_verified
            ));
        } else {
            out.push_str("  result: FAILED\n");
            if let Some(ref e) = self.error {
                out.push_str(&format!("  error:  {}\n", e));
            }
        }
        out
    }
}

// -- publish / rollback --

pub fn publish(
    store_path: &Path,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let sub = log
        .build_witness_submission(stream)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    // Emit JSON regardless of format so users can pipe into curl.
    // When format=text, print a human-readable header + the JSON.
    match format {
        OutputFormat::Json | OutputFormat::Yaml | OutputFormat::Dot => {
            println!("{}", serde_json::to_string_pretty(&sub)?);
        }
        OutputFormat::Text => {
            println!("witness submission for stream={}:", stream);
            println!("{}", serde_json::to_string_pretty(&sub)?);
            println!();
            println!("POST this to your witness endpoint, e.g.:");
            println!(
                "  curl -X POST -H 'content-type: application/json' \\\n    -d @submission.json \\\n    http://localhost:7701/v1/audit/witness"
            );
        }
    }
    Ok(())
}

pub fn rollback_check(
    store_path: &Path,
    backend: &dyn TpmBackend,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let log = open_log(store_path)?;
    let id_store = Store::open(store_path)?;
    let signer = TpmCheckpointSigner::new(backend, &id_store);
    match log.check_rollback(&signer, stream) {
        Ok(()) => {
            let rec = log.head_record(stream).ok().flatten();
            let out = RollbackOutput {
                stream: stream.to_string(),
                ok: true,
                error: None,
                head_segment_id: rec.as_ref().map(|r| r.segment_id),
                head_seq_end: rec.as_ref().map(|r| r.seq_end),
                head_hash: rec.map(|r| r.checkpoint_hash_hex),
            };
            println!("{}", render(&out, format));
            Ok(())
        }
        Err(e) => {
            let out = RollbackOutput {
                stream: stream.to_string(),
                ok: false,
                error: Some(e.to_string()),
                head_segment_id: None,
                head_seq_end: None,
                head_hash: None,
            };
            println!("{}", render(&out, format));
            anyhow::bail!("rollback detected: {}", e);
        }
    }
}

#[derive(Serialize)]
struct RollbackOutput {
    stream: String,
    ok: bool,
    error: Option<String>,
    head_segment_id: Option<u64>,
    head_seq_end: Option<u64>,
    head_hash: Option<String>,
}

impl TextRenderable for RollbackOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("rollback check: stream={}\n", self.stream));
        if self.ok {
            out.push_str("  result: ok (no rollback detected)\n");
            if let (Some(sid), Some(seq_end)) = (self.head_segment_id, self.head_seq_end) {
                out.push_str(&format!(
                    "  head_file:  segment={} seq_end={}\n",
                    sid, seq_end
                ));
                if let Some(ref h) = self.head_hash {
                    out.push_str(&format!("  head_hash:  {}\n", h));
                }
            } else {
                out.push_str("  head_file:  (empty or disabled)\n");
            }
        } else {
            out.push_str("  result: FAILED\n");
            if let Some(ref e) = self.error {
                out.push_str(&format!("  error:  {}\n", e));
            }
        }
        out
    }
}

// -- Witness subcommands -------------------------------------------------------

#[derive(serde::Serialize)]
struct WitnessRow {
    id: Option<i64>,
    stream_id: String,
    segment_id: u64,
    seq_start: u64,
    seq_end: u64,
    checkpoint_hash: String,
    signer: String,
    received_at: String,
}

impl TextRenderable for WitnessRow {
    fn render_text(&self) -> String {
        format!(
            "id={} stream={} seg={} seqs={}-{} signer={} received={}\n",
            self.id.map(|i| i.to_string()).unwrap_or_default(),
            self.stream_id,
            self.segment_id,
            self.seq_start,
            self.seq_end,
            self.signer,
            self.received_at,
        )
    }
}

#[derive(serde::Serialize)]
struct WitnessListOutput {
    witnesses: Vec<WitnessRow>,
}

impl TextRenderable for WitnessListOutput {
    fn render_text(&self) -> String {
        if self.witnesses.is_empty() {
            return "no witness receipts\n".to_string();
        }
        self.witnesses.iter().map(|w| w.render_text()).collect()
    }
}

fn to_witness_row(r: tpm_core::store::WitnessLogRow) -> WitnessRow {
    WitnessRow {
        id: r.id,
        stream_id: r.stream_id,
        segment_id: r.segment_id,
        seq_start: r.seq_start,
        seq_end: r.seq_end,
        checkpoint_hash: r.checkpoint_hash_hex,
        signer: r.signer_identity,
        received_at: r.received_at_rfc3339,
    }
}

pub fn witness_list(
    store_path: &Path,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let store = Store::open(store_path)?;
    let rows = store.witness_log_list(stream)?;
    let out = WitnessListOutput {
        witnesses: rows.into_iter().map(to_witness_row).collect(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn witness_latest(
    store_path: &Path,
    stream: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let store = Store::open(store_path)?;
    match store.witness_log_latest(stream)? {
        Some(row) => println!("{}", render(&to_witness_row(row), format)),
        None => println!("no witness receipts for stream '{}'", stream),
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct WitnessGcReport {
    streams_scanned: usize,
    receipts_deleted: usize,
    dry_run: bool,
}

impl TextRenderable for WitnessGcReport {
    fn render_text(&self) -> String {
        if self.dry_run {
            format!(
                "dry-run: would delete {} receipt(s) across {} stream(s)\n",
                self.receipts_deleted, self.streams_scanned
            )
        } else {
            format!(
                "deleted {} receipt(s) across {} stream(s)\n",
                self.receipts_deleted, self.streams_scanned
            )
        }
    }
}

pub fn witness_gc(
    store_path: &Path,
    stream: &str,
    keep_latest: Option<usize>,
    older_than: Option<&str>,
    dry_run: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if keep_latest.is_none() && older_than.is_none() {
        anyhow::bail!("at least one of --keep-latest or --older-than must be specified");
    }

    let store = Store::open(store_path)?;
    let stream_arg = if stream == "all" { None } else { Some(stream) };

    let streams_scanned = if stream == "all" {
        store.witness_log_stream_ids()?.len()
    } else {
        1
    };

    if dry_run {
        let would_delete = count_gc_candidates(&store, stream_arg, keep_latest, older_than)?;
        let report = WitnessGcReport {
            streams_scanned,
            receipts_deleted: would_delete,
            dry_run: true,
        };
        println!("{}", render(&report, format));
        return Ok(());
    }

    let deleted = store.witness_log_gc(stream_arg, keep_latest, older_than)?;
    store.log_action(
        "audit.witness.gc",
        stream_arg,
        &serde_json::json!({
            "deleted": deleted,
            "keep_latest": keep_latest,
            "older_than": older_than,
        }),
    )?;
    let report = WitnessGcReport {
        streams_scanned,
        receipts_deleted: deleted,
        dry_run: false,
    };
    println!("{}", render(&report, format));
    Ok(())
}

/// Count GC candidates without deleting (for --dry-run).
fn count_gc_candidates(
    store: &Store,
    stream_id: Option<&str>,
    keep_latest: Option<usize>,
    older_than: Option<&str>,
) -> anyhow::Result<usize> {
    let streams: Vec<String> = if let Some(sid) = stream_id {
        vec![sid.to_string()]
    } else {
        store.witness_log_stream_ids()?
    };

    let mut count = 0usize;
    for sid in &streams {
        let rows = store.witness_log_list(sid)?;
        let keep_set: std::collections::HashSet<Option<i64>> = if let Some(k) = keep_latest {
            rows.iter().map(|r| r.id).rev().take(k).collect()
        } else {
            std::collections::HashSet::new()
        };
        for row in &rows {
            if !keep_set.is_empty() && keep_set.contains(&row.id) {
                continue;
            }
            if let Some(cutoff) = older_than {
                if row.received_at_rfc3339.as_str() >= cutoff {
                    continue;
                }
            } else if keep_set.is_empty() {
                continue; // no filter active
            }
            count += 1;
        }
    }
    Ok(count)
}

pub fn witness_record(
    store_path: &Path,
    input: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let json_str = if input == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(input)?
    };

    let sub: WitnessSubmission = serde_json::from_str(&json_str)
        .map_err(|e| anyhow::anyhow!("invalid witness submission JSON: {}", e))?;

    let store = Store::open(store_path)?;
    let row = tpm_core::store::WitnessLogRow {
        id: None,
        stream_id: sub.stream_id.clone(),
        segment_id: sub.segment_id,
        seq_start: sub.seq_start,
        seq_end: sub.seq_end,
        checkpoint_hash_hex: sub.checkpoint_hash_hex,
        signature_hex: sub.signature_hex,
        signer_identity: sub.signer_identity,
        received_at_rfc3339: chrono::Utc::now().to_rfc3339(),
    };
    let id = store.witness_log_insert(&row)?;
    store.log_action(
        "audit.witness.record",
        Some(&sub.stream_id),
        &serde_json::json!({"segment_id": sub.segment_id, "row_id": id}),
    )?;
    let recorded = store.witness_log_list(&sub.stream_id)?.into_iter()
        .find(|r| r.id == Some(id as i64))
        .map(to_witness_row)
        .ok_or_else(|| anyhow::anyhow!("failed to retrieve recorded row"))?;
    println!("{}", render(&recorded, format));
    Ok(())
}
