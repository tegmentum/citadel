//! `tpm measure` — application/artifact measurement on top of the
//! tamper-evident secure log.
//!
//! Measurements are recorded as leaves on a dedicated `measurement`
//! secure-log stream. Closing a segment seals a Merkle root over the
//! pending measurements; signing the segment anchors that root with a
//! TPM-backed identity key (the "key signs a particular hash" model).
//! Inclusion proofs then show that a given artifact was measured.
//!
//! Two sourcing modes are supported:
//!   - direct: citadel hashes an artifact itself (`tpm measure file`).
//!   - delegated: citadel ingests the kernel's IMA runtime measurement
//!     list (`tpm measure ima`) and anchors it.
//!
//! Checkpoint/sign/verify reuse the audit secure-log commands with the
//! `measurement` stream, so the Merkle/signing machinery is shared.

use std::path::Path;

use tpm_core::backend::{hash_for_bank, TpmBackend};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;

use serde::Serialize;

use super::audit;

/// The dedicated stream that holds application measurements.
pub const MEASUREMENT_STREAM: &str = "measurement";

/// Default location of the kernel IMA runtime measurement list.
const IMA_DEFAULT_PATH: &str = "/sys/kernel/security/ima/ascii_runtime_measurements";

// -- direct measurement: tpm measure file <artifact> --

#[allow(clippy::too_many_arguments)]
pub fn file(
    store_path: &Path,
    backend: &dyn TpmBackend,
    artifact: &Path,
    kind: &str,
    bank: &str,
    pcr: Option<u32>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let data = std::fs::read(artifact)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", artifact.display()))?;
    let digest = hash_for_bank(bank, &data)?;
    let digest_hex = hex(&digest);
    let artifact_id = artifact.to_string_lossy().to_string();

    // Optionally fold the measurement into a PCR as well.
    if let Some(index) = pcr {
        backend.pcr_extend(bank, index, &digest)?;
    }

    let payload = serde_json::json!({
        "source": "direct",
        "artifact_id": artifact_id,
        "kind": kind,
        "digest_alg": bank,
        "digest": digest_hex,
        "size": data.len(),
        "pcr": pcr,
    })
    .to_string();

    let seqno = append_measurement(store_path, backend, "artifact.measure", &payload)?;

    let out = MeasureFileOutput {
        seqno,
        stream: MEASUREMENT_STREAM.to_string(),
        artifact_id,
        kind: kind.to_string(),
        digest_alg: bank.to_string(),
        digest: digest_hex,
        pcr,
    };
    println!("{}", render(&out, format));
    Ok(())
}

// -- self-enrollment: tpm measure enroll --

/// Enroll Citadel itself into the MMA by measuring the running executable
/// — the agent's own self-measurement at the root of the application
/// branch. With `--pcr`, also extend the digest into a PCR so the agent's
/// signing identity can be bound to it (combine with
/// `tpm identity init --pcr-bind`).
///
/// Note: a self-measurement via the running binary is self-attestation —
/// a tampered agent can report a false hash. It becomes a real anchor
/// only when Citadel is itself measured from below (IMA / a measured
/// launcher); the enrolled digest is then cross-checkable.
pub fn enroll(
    store_path: &Path,
    backend: &dyn TpmBackend,
    bank: &str,
    pcr: Option<u32>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("locating the Citadel executable: {e}"))?;
    let data = std::fs::read(&exe).map_err(|e| anyhow::anyhow!("reading {}: {e}", exe.display()))?;
    let digest = hash_for_bank(bank, &data)?;
    let digest_hex = hex(&digest);

    if let Some(index) = pcr {
        if !pcr_persists(index) {
            eprintln!(
                "warning: PCR {} resets each boot (not in the Startup(STATE) save set); \
                 the agent measurement will not persist across invocations. Use a PCR in 0-15.",
                index
            );
        }
        backend.pcr_extend(bank, index, &digest)?;
    }

    let payload = serde_json::json!({
        "source": "self",
        "artifact_id": "citadel",
        "kind": "agent",
        "digest_alg": bank,
        "digest": digest_hex,
        "path": exe.to_string_lossy(),
        "version": env!("CARGO_PKG_VERSION"),
        "pcr": pcr,
    })
    .to_string();

    let seqno = append_measurement(store_path, backend, "agent.enroll", &payload)?;

    let out = EnrollOutput {
        seqno,
        digest_alg: bank.to_string(),
        digest: digest_hex,
        path: exe.to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pcr,
    };
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct EnrollOutput {
    seqno: u64,
    digest_alg: String,
    digest: String,
    path: String,
    version: String,
    pcr: Option<u32>,
}

impl TextRenderable for EnrollOutput {
    fn render_text(&self) -> String {
        let mut out = format!(
            "enrolled Citadel into the MMA\n  seqno:    {}\n  version:  {}\n  path:     {}\n  {}:  {}\n",
            self.seqno, self.version, self.path, self.digest_alg, self.digest
        );
        match self.pcr {
            Some(i) => out.push_str(&format!("  pcr:      extended {}[{}]\n", self.digest_alg, i)),
            None => out.push_str("  pcr:      (not extended)\n"),
        }
        out
    }
}

// -- delegated measurement: tpm measure ima [--from <path>] --

pub fn ima(
    store_path: &Path,
    backend: &dyn TpmBackend,
    from: Option<&Path>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = from.unwrap_or_else(|| Path::new(IMA_DEFAULT_PATH));
    let contents = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "reading IMA measurements from {}: {e}\n\
             (provide --from <file> when not running on a Linux host with IMA)",
            path.display()
        )
    })?;

    let mut ingested = 0u64;
    let mut last_seqno = 0u64;
    for line in contents.lines() {
        let Some(entry) = parse_ima_line(line) else {
            continue;
        };
        let payload = serde_json::json!({
            "source": "ima",
            "artifact_id": entry.filename,
            "kind": "ima",
            "digest_alg": entry.digest_alg,
            "digest": entry.file_digest,
            "ima_pcr": entry.pcr,
            "template": entry.template,
            "template_hash": entry.template_hash,
        })
        .to_string();
        last_seqno = append_measurement(store_path, backend, "ima.measure", &payload)?;
        ingested += 1;
    }

    let out = ImaImportOutput {
        source: path.to_string_lossy().to_string(),
        ingested,
        last_seqno,
        stream: MEASUREMENT_STREAM.to_string(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

// -- anchoring / verification: delegate to the audit secure-log ---

/// Seal a Merkle segment over the pending measurements (the tree root),
/// optionally anchoring the root into a PCR so secrets can be sealed to
/// the attested measurement set (`--extend-pcr`).
pub fn checkpoint(
    store_path: &Path,
    backend: &dyn TpmBackend,
    extend_pcr: Option<u32>,
    bank: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let seg = audit::close_segment_value(store_path, MEASUREMENT_STREAM)?;

    if let Some(index) = extend_pcr {
        // PCRs 0-15 are in the TPM's Startup(STATE) save set and persist
        // across invocations; 16-23 reset each boot, so an anchor there
        // can't back a cross-invocation seal-to-attested-set.
        if !pcr_persists(index) {
            eprintln!(
                "warning: PCR {} resets each boot (not in the Startup(STATE) save set); \
                 the measurement anchor will not persist across invocations. \
                 Use a PCR in 0-15 (e.g. the default 14).",
                index
            );
        }
        // The Merkle root is a bank-sized digest; fold it into the PCR.
        backend.pcr_extend(bank, index, &seg.merkle_root)?;
    }

    let out = CheckpointOutput {
        stream: MEASUREMENT_STREAM.to_string(),
        segment_id: seg.segment_id,
        seq_range: format!("[{}, {}]", seg.seq_start, seg.seq_end),
        merkle_root: hex(&seg.merkle_root),
        extended_pcr: extend_pcr.map(|i| format!("{}[{}]", bank, i)),
    };
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct CheckpointOutput {
    stream: String,
    segment_id: u64,
    seq_range: String,
    merkle_root: String,
    extended_pcr: Option<String>,
}

impl TextRenderable for CheckpointOutput {
    fn render_text(&self) -> String {
        let mut out = format!(
            "sealed measurement checkpoint\n  stream:      {}\n  segment:     {} {}\n  merkle_root: {}\n",
            self.stream, self.segment_id, self.seq_range, self.merkle_root
        );
        match &self.extended_pcr {
            Some(p) => out.push_str(&format!("  anchored to: PCR {}\n", p)),
            None => out.push_str("  anchored to: (not extended into a PCR)\n"),
        }
        out
    }
}

/// Anchor a sealed segment's root by signing it with a TPM identity.
///
/// When `require_baseline` is set, the signing key is gated on the live
/// PCRs matching that saved baseline — binding the anchoring key to a
/// known-good measured state.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    store_path: &Path,
    backend: &dyn TpmBackend,
    segment_id: u64,
    identity: &str,
    require_baseline: Option<&str>,
    anti_rollback: Option<u32>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    audit::sign(
        store_path,
        backend,
        segment_id,
        identity,
        require_baseline,
        anti_rollback,
        format,
    )
}

/// Detect log truncation/rollback: the live NV counter must not have
/// advanced past the highest counter bound into a recorded checkpoint
/// (which would mean checkpoints were signed and then removed).
pub fn rollback_check(
    store_path: &Path,
    backend: &dyn TpmBackend,
    nv_index: Option<u32>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let index = nv_index.unwrap_or(ANCHOR_COUNTER_NV_INDEX);
    let live = backend.nv_read_counter(index)?;
    let store = tpm_core::store::Store::open(store_path)?;
    let max_recorded = store.max_checkpoint_counter()?;

    let (ok, detail) = match (live, max_recorded) {
        (Some(l), Some(m)) if l > m => (
            false,
            format!("live NV counter {l} exceeds the latest checkpoint counter {m}: {} checkpoint(s) appear to have been removed", l - m),
        ),
        (Some(l), Some(m)) => (true, format!("live NV counter {l} matches the latest checkpoint counter {m}")),
        _ => (true, "no anti-rollback counters recorded (sign with --anti-rollback to enable)".to_string()),
    };

    let out = RollbackCheckOutput {
        nv_index: format!("0x{:08X}", index),
        live_counter: live,
        latest_checkpoint_counter: max_recorded,
        ok,
        detail,
    };
    println!("{}", render(&out, format));
    if !ok {
        anyhow::bail!("rollback detected");
    }
    Ok(())
}

#[derive(Serialize)]
struct RollbackCheckOutput {
    nv_index: String,
    live_counter: Option<u64>,
    latest_checkpoint_counter: Option<u64>,
    ok: bool,
    detail: String,
}

impl TextRenderable for RollbackCheckOutput {
    fn render_text(&self) -> String {
        format!(
            "anti-rollback check\n  nv_index:           {}\n  live counter:       {}\n  latest checkpoint:  {}\n  result: {}\n  {}\n",
            self.nv_index,
            self.live_counter.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
            self.latest_checkpoint_counter.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
            if self.ok { "OK" } else { "ROLLBACK DETECTED" },
            self.detail,
        )
    }
}

/// Prove that a measurement (by seqno) is included under a sealed root.
pub fn verify(store_path: &Path, seqno: u64, format: OutputFormat) -> anyhow::Result<()> {
    audit::prove(store_path, seqno, format)
}

/// List sealed measurement segments (the Merkle roots).
pub fn list(store_path: &Path, format: OutputFormat) -> anyhow::Result<()> {
    audit::segments_list(store_path, MEASUREMENT_STREAM, format)
}

/// Default NV index for the measurement anti-rollback counter.
const ANCHOR_COUNTER_NV_INDEX: u32 = 0x0180_0001;

/// Increment the monotonic anti-rollback counter and report its value.
///
/// On real TPMs this maps to a counter-type NV index (`TPM2_NV_Increment`)
/// that can never decrease, so a replayed old checkpoint carries a stale
/// counter the live value exceeds. Binding the counter value into the
/// signed checkpoint (so verification can compare) requires secure-log
/// support and is tracked as remaining work; this exposes the primitive.
pub fn anchor_counter(
    backend: &dyn TpmBackend,
    nv_index: Option<u32>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let index = nv_index.unwrap_or(ANCHOR_COUNTER_NV_INDEX);
    let value = backend.nv_increment(index)?;
    let out = AnchorCounterOutput {
        nv_index: format!("0x{:08X}", index),
        value,
    };
    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct AnchorCounterOutput {
    nv_index: String,
    value: u64,
}

impl TextRenderable for AnchorCounterOutput {
    fn render_text(&self) -> String {
        format!(
            "anti-rollback counter\n  nv_index: {}\n  value:    {}\n",
            self.nv_index, self.value
        )
    }
}

// -- helpers --

fn append_measurement(
    store_path: &Path,
    backend: &dyn TpmBackend,
    event: &str,
    payload_json: &str,
) -> anyhow::Result<u64> {
    ensure_stream(store_path)?;
    audit::append_value(
        store_path,
        backend,
        MEASUREMENT_STREAM,
        event,
        "info",
        "measure",
        payload_json.as_bytes(),
        false,
    )
}

/// Declare the measurement stream (idempotent) so appends don't warn.
/// Tier is `public`: measurements are digests, not secrets, and a
/// protected tier would force envelope encryption (needs a master KEK).
fn ensure_stream(store_path: &Path) -> anyhow::Result<()> {
    use tpm_core::store::{SecureLogStreamRow, Store};
    let store = Store::open(store_path)?;
    if store.secure_log_stream_get(MEASUREMENT_STREAM)?.is_some() {
        return Ok(());
    }
    store.secure_log_stream_upsert(&SecureLogStreamRow {
        name: MEASUREMENT_STREAM.to_string(),
        tier: "public".to_string(),
        description: Some("application/artifact measurements".to_string()),
        created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
        deprecated_at_rfc3339: None,
    })?;
    Ok(())
}

struct ImaEntry {
    pcr: String,
    template_hash: String,
    template: String,
    digest_alg: String,
    file_digest: String,
    filename: String,
}

/// Parse one line of `ascii_runtime_measurements`.
///
/// Format: `<pcr> <template-hash> <template-name> <filedata-hash> <filename>`
/// where `<filedata-hash>` is either `alg:hex` (ima-ng/ima-sig) or bare
/// hex (legacy `ima` template).
fn parse_ima_line(line: &str) -> Option<ImaEntry> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 5 {
        return None;
    }
    let (digest_alg, file_digest) = match f[3].split_once(':') {
        Some((alg, hex)) => (alg.to_string(), hex.to_string()),
        None => ("unknown".to_string(), f[3].to_string()),
    };
    Some(ImaEntry {
        pcr: f[0].to_string(),
        template_hash: f[1].to_string(),
        template: f[2].to_string(),
        digest_alg,
        file_digest,
        // filename may contain spaces in theory; join the remainder.
        filename: f[4..].join(" "),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Whether a PCR index is in the TPM Startup(STATE) save set, and so
/// persists across invocations. PCRs 0-15 are saved; 16-23 reset.
fn pcr_persists(index: u32) -> bool {
    index < 16
}

#[derive(Serialize)]
struct MeasureFileOutput {
    seqno: u64,
    stream: String,
    artifact_id: String,
    kind: String,
    digest_alg: String,
    digest: String,
    pcr: Option<u32>,
}

impl TextRenderable for MeasureFileOutput {
    fn render_text(&self) -> String {
        let mut out = format!(
            "measured {} ({})\n  seqno:  {}\n  {}:  {}\n",
            self.artifact_id, self.kind, self.seqno, self.digest_alg, self.digest
        );
        match self.pcr {
            Some(i) => out.push_str(&format!("  pcr:    extended {}[{}]\n", self.digest_alg, i)),
            None => out.push_str("  pcr:    (not extended)\n"),
        }
        out
    }
}

#[derive(Serialize)]
struct ImaImportOutput {
    source: String,
    ingested: u64,
    last_seqno: u64,
    stream: String,
}

impl TextRenderable for ImaImportOutput {
    fn render_text(&self) -> String {
        format!(
            "ingested {} IMA measurement(s) from {}\n  stream: {}\n  last seqno: {}\n",
            self.ingested, self.source, self.stream, self.last_seqno
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ima_ng_line() {
        let line =
            "10 a1b2c3 ima-ng sha256:deadbeef /usr/bin/bash";
        let e = parse_ima_line(line).expect("should parse");
        assert_eq!(e.pcr, "10");
        assert_eq!(e.template, "ima-ng");
        assert_eq!(e.digest_alg, "sha256");
        assert_eq!(e.file_digest, "deadbeef");
        assert_eq!(e.filename, "/usr/bin/bash");
    }

    #[test]
    fn parses_legacy_ima_line_without_alg_prefix() {
        let line = "10 a1b2c3 ima 0011223344 /sbin/init";
        let e = parse_ima_line(line).expect("should parse");
        assert_eq!(e.digest_alg, "unknown");
        assert_eq!(e.file_digest, "0011223344");
        assert_eq!(e.filename, "/sbin/init");
    }

    #[test]
    fn rejects_short_line() {
        assert!(parse_ima_line("10 abc ima-ng").is_none());
        assert!(parse_ima_line("").is_none());
    }

    /// Anti-rollback: a counter bound into a checkpoint round-trips
    /// through verification, and advancing the live NV counter past the
    /// recorded checkpoints is detected as truncation/rollback.
    #[test]
    fn anti_rollback_binding_round_trips_and_detects_truncation() {
        use crate::commands::audit;
        use tpm_core::backend::MockBackend;
        use tpm_core::store::Store;

        let db = tempfile::NamedTempFile::new().unwrap();
        let path = db.path();
        let backend = MockBackend::new();
        let store = Store::open(path).unwrap();

        crate::commands::identity::init(
            &store, &backend, "auditor", "generic", "ecc-p256", None, None, None, None,
            OutputFormat::Json,
        )
        .unwrap();

        let app = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(app.path(), b"workload").unwrap();
        file(path, &backend, app.path(), "binary", "sha256", None, OutputFormat::Json).unwrap();
        checkpoint(path, &backend, None, "sha256", OutputFormat::Json).unwrap();

        // Sign with anti-rollback: binds NV counter 1 into the checkpoint.
        sign(path, &backend, 1, "auditor", None, Some(ANCHOR_COUNTER_NV_INDEX), OutputFormat::Json)
            .unwrap();

        // The checkpoint chain verifies (the bound counter is reconstructed).
        assert_eq!(
            audit::verify_checkpoint_chain(path, &backend, MEASUREMENT_STREAM).unwrap(),
            1
        );

        // Live NV (1) matches the latest checkpoint counter (1): no rollback.
        rollback_check(path, &backend, Some(ANCHOR_COUNTER_NV_INDEX), OutputFormat::Json).unwrap();

        // Advance the NV counter without recording a checkpoint, as if a
        // signed checkpoint were removed: now detected.
        anchor_counter(&backend, Some(ANCHOR_COUNTER_NV_INDEX), OutputFormat::Json).unwrap();
        let err = rollback_check(path, &backend, Some(ANCHOR_COUNTER_NV_INDEX), OutputFormat::Json)
            .expect_err("advancing the live counter past recorded checkpoints is a rollback");
        assert!(err.to_string().contains("rollback"), "unexpected error: {err}");
    }

    #[test]
    fn pcr_save_set_boundary() {
        assert!(pcr_persists(0));
        assert!(pcr_persists(14));
        assert!(pcr_persists(15));
        assert!(!pcr_persists(16));
        assert!(!pcr_persists(23));
    }

    /// Capstone: measure -> checkpoint (anchor root into a PCR) -> seal a
    /// secret to that PCR. The secret unseals while the attested set is
    /// unchanged, then is refused once a new measurement changes the
    /// anchored PCR. Exercises Phases 0/1/2/5 together in one process.
    #[test]
    fn seal_to_attested_set_breaks_when_the_measured_set_changes() {
        use crate::commands::secret;
        use tpm_core::backend::MockBackend;
        use tpm_core::model::{Policy, PolicyRule};
        use tpm_core::store::Store;
        use uuid::Uuid;

        let db = tempfile::NamedTempFile::new().unwrap();
        let path = db.path();
        let backend = MockBackend::new();
        let store = Store::open(path).unwrap();

        // Bind a policy to the measurement-anchor PCR.
        store
            .insert_policy(&Policy {
                id: Uuid::new_v4(),
                name: "attested".to_string(),
                rules: vec![PolicyRule::PcrMatch {
                    bank: "sha256".to_string(),
                    indices: vec![23],
                }],
            })
            .unwrap();

        let app1 = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(app1.path(), b"app-v1").unwrap();
        let secret_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret_file.path(), b"deploy-key").unwrap();

        // Measure v1 and anchor the Merkle root into PCR 23.
        file(path, &backend, app1.path(), "binary", "sha256", None, OutputFormat::Json).unwrap();
        checkpoint(path, &backend, Some(23), "sha256", OutputFormat::Json).unwrap();

        // Seal a secret to the attested set; it unseals now.
        secret::seal(&store, &backend, "secret/deploy", secret_file.path(), Some("attested"), OutputFormat::Json).unwrap();
        secret::unseal(&store, &backend, "secret/deploy", None, OutputFormat::Json)
            .expect("unseals while the attested set is unchanged");

        // A new measurement changes the anchored PCR (the attested set).
        let app2 = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(app2.path(), b"app-v2-rogue").unwrap();
        file(path, &backend, app2.path(), "binary", "sha256", None, OutputFormat::Json).unwrap();
        checkpoint(path, &backend, Some(23), "sha256", OutputFormat::Json).unwrap();

        // The secret is now sealed to a state that no longer holds.
        let err = secret::unseal(&store, &backend, "secret/deploy", None, OutputFormat::Json)
            .expect_err("unseal must be refused after the measured set changes");
        assert!(
            err.to_string().contains("PCR policy not satisfied"),
            "unexpected error: {err}"
        );
    }
}
