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

/// Seal a Merkle segment over the pending measurements (the tree root).
pub fn checkpoint(store_path: &Path, format: OutputFormat) -> anyhow::Result<()> {
    audit::segments_close(store_path, MEASUREMENT_STREAM, format)
}

/// Anchor a sealed segment's root by signing it with a TPM identity.
pub fn sign(
    store_path: &Path,
    backend: &dyn TpmBackend,
    segment_id: u64,
    identity: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    audit::sign(store_path, backend, segment_id, identity, format)
}

/// Prove that a measurement (by seqno) is included under a sealed root.
pub fn verify(store_path: &Path, seqno: u64, format: OutputFormat) -> anyhow::Result<()> {
    audit::prove(store_path, seqno, format)
}

/// List sealed measurement segments (the Merkle roots).
pub fn list(store_path: &Path, format: OutputFormat) -> anyhow::Result<()> {
    audit::segments_list(store_path, MEASUREMENT_STREAM, format)
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
}
