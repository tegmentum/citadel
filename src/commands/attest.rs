use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::TpmBackend;
use tpm_core::diag::TpmError;
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, TpmObject};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::{Deserialize, Serialize};

use super::audit;

/// A signed measurement checkpoint bundled into a quote so a verifier
/// gets boot-state attestation and the anchored measurement root in one
/// artifact. The root is the Merkle root over the measured set; the
/// signature is produced by the measurement identity (whose key use is
/// gated on measured state — see `measure sign --require-baseline`).
#[derive(Serialize, Deserialize, Clone)]
struct MeasurementCheckpoint {
    stream: String,
    segment_id: u64,
    seq_start: u64,
    seq_end: u64,
    merkle_root: String,
    signature: String,
    signer_identity: Option<String>,
}

/// A quote optionally bundled with a measurement checkpoint. Written by
/// `attest quote --with-measurements`; `attest quote` without the flag
/// still writes a bare `QuoteData` for backward compatibility.
#[derive(Serialize, Deserialize)]
struct QuoteBundle {
    quote: tpm_core::backend::QuoteData,
    #[serde(default)]
    measurement_checkpoint: Option<MeasurementCheckpoint>,
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// -- ak create --

pub fn ak_create(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    algorithm_str: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(name)?;

    if store.get_object(&path)?.is_some() {
        let err = TpmError::object_already_exists(name);
        err.emit();
        return Err(err.into());
    }

    let algorithm: Algorithm = algorithm_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let handle = backend.create_ak(algorithm)?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::AttestationKey,
        algorithm,
        policy_id: None,
        handle_blob: Some(handle.id.clone()),
        created_at: Utc::now(),
        metadata: serde_json::json!({"type": "attestation_key"}),
    };

    store.insert_object(&obj)?;
    store.log_action(
        "ak.create",
        Some(path.as_str()),
        &serde_json::json!({"algorithm": algorithm.to_string()}),
    )?;

    let result = AkCreated {
        path: path.to_string(),
        id: obj.id.to_string(),
        algorithm: algorithm.to_string(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct AkCreated {
    path: String,
    id: String,
    algorithm: String,
}

impl TextRenderable for AkCreated {
    fn render_text(&self) -> String {
        format!(
            "attestation key created: {}\n  id: {}\n  algorithm: {}\n",
            self.path, self.id, self.algorithm
        )
    }
}

// -- quote --

#[allow(clippy::too_many_arguments)]
pub fn quote(
    store: &Store,
    backend: &dyn TpmBackend,
    store_path: &std::path::Path,
    ak_name: &str,
    pcr_bank: &str,
    pcr_indices: &[u32],
    nonce: Option<&str>,
    with_measurements: Option<&str>,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let ak_path = ObjectPath::new(ak_name)?;
    let ak_obj = store.get_object(&ak_path)?.ok_or_else(|| {
        let err = TpmError::object_not_found(ak_name);
        err.emit();
        err
    })?;

    if ak_obj.kind != ObjectKind::AttestationKey {
        let err = TpmError::type_mismatch(ak_name, "attestation key", &ak_obj.kind.to_string());
        err.emit();
        return Err(err.into());
    }

    let ak_handle = tpm_core::backend::KeyHandle {
        id: ak_obj
            .handle_blob
            .clone()
            .unwrap_or_default(),
        path: ak_name.to_string(),
    };

    // Generate or use provided nonce
    let nonce_bytes = match nonce {
        Some(n) => n.as_bytes().to_vec(),
        None => {
            let mut n = vec![0u8; 32];
            for (i, b) in n.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(0x37).wrapping_add(0xAB);
            }
            n
        }
    };

    let quote_data = backend.quote(&ak_handle, &nonce_bytes, pcr_bank, pcr_indices)?;

    // Optionally bundle the latest signed measurement checkpoint so the
    // verifier gets boot-state attestation + the anchored measurement
    // root together.
    let checkpoint = if let Some(stream) = with_measurements {
        match audit::latest_signed_segment(store_path, stream)? {
            Some(seg) => Some(MeasurementCheckpoint {
                stream: stream.to_string(),
                segment_id: seg.segment_id,
                seq_start: seg.seq_start,
                seq_end: seg.seq_end,
                merkle_root: hex_bytes(&seg.merkle_root),
                signature: hex_bytes(&seg.signature),
                signer_identity: seg.signer_identity.clone(),
            }),
            None => anyhow::bail!(
                "no signed measurement segment on stream '{}'; run `tpm measure checkpoint` then `tpm measure sign`",
                stream
            ),
        }
    } else {
        None
    };

    // Save to file if requested. With measurements we write a bundle;
    // without, a bare QuoteData (backward compatible).
    if let Some(out_path) = output {
        let json = if checkpoint.is_some() {
            serde_json::to_string_pretty(&QuoteBundle {
                quote: quote_data.clone(),
                measurement_checkpoint: checkpoint.clone(),
            })?
        } else {
            serde_json::to_string_pretty(&quote_data)?
        };
        std::fs::write(out_path, json)?;
    }

    store.log_action(
        "quote.generate",
        Some(ak_name),
        &serde_json::json!({
            "pcr_bank": pcr_bank,
            "pcr_indices": pcr_indices,
        }),
    )?;

    let result = QuoteResult {
        ak: ak_name.to_string(),
        pcr_bank: pcr_bank.to_string(),
        pcr_count: pcr_indices.len(),
        nonce_hex: hex_encode(&nonce_bytes),
        attestation_hex: hex_encode(&quote_data.attestation),
        signature_hex: hex_encode(&quote_data.signature),
        measurement_root: checkpoint.as_ref().map(|c| c.merkle_root.clone()),
        output_file: output.map(|p| p.display().to_string()),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct QuoteResult {
    ak: String,
    pcr_bank: String,
    pcr_count: usize,
    nonce_hex: String,
    attestation_hex: String,
    signature_hex: String,
    measurement_root: Option<String>,
    output_file: Option<String>,
}

impl TextRenderable for QuoteResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("quote generated\n"));
        out.push_str(&format!("  ak:          {}\n", self.ak));
        out.push_str(&format!("  PCR bank:    {}\n", self.pcr_bank));
        out.push_str(&format!("  PCRs:        {}\n", self.pcr_count));
        out.push_str(&format!("  nonce:       {}\n", self.nonce_hex));
        out.push_str(&format!("  attestation: {}\n", self.attestation_hex));
        out.push_str(&format!("  signature:   {}\n", self.signature_hex));
        if let Some(ref r) = self.measurement_root {
            out.push_str(&format!("  meas. root:  {}\n", r));
        }
        if let Some(ref f) = self.output_file {
            out.push_str(&format!("  written to:  {}\n", f));
        }
        out
    }
}

// -- quote verify --

pub fn verify(
    backend: &dyn TpmBackend,
    store_path: &std::path::Path,
    quote_path: &std::path::Path,
    nonce: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(quote_path)?;
    // Accept either a measurement bundle or a bare QuoteData.
    let (quote_data, checkpoint): (tpm_core::backend::QuoteData, Option<MeasurementCheckpoint>) =
        match serde_json::from_str::<QuoteBundle>(&json) {
            Ok(bundle) => (bundle.quote, bundle.measurement_checkpoint),
            Err(_) => (serde_json::from_str(&json)?, None),
        };

    let nonce_bytes = match nonce {
        Some(n) => n.as_bytes().to_vec(),
        None => quote_data.nonce.clone(),
    };

    let verification =
        backend.verify_quote(&quote_data, &quote_data.ak_public, &nonce_bytes)?;

    // If a measurement checkpoint was bundled, verify its signature
    // chain against the local secure log: this confirms the measurement
    // root was anchored by the (measured-state-gated) signing identity.
    let measurement = match &checkpoint {
        Some(c) => {
            let result = audit::verify_checkpoint_chain(store_path, backend, &c.stream);
            Some(MeasurementVerify {
                stream: c.stream.clone(),
                segment_id: c.segment_id,
                merkle_root: c.merkle_root.clone(),
                seq_range: format!("[{}, {}]", c.seq_start, c.seq_end),
                signer_identity: c.signer_identity.clone(),
                checkpoint_chain_ok: result.is_ok(),
                error: result.err().map(|e| e.to_string()),
            })
        }
        None => None,
    };

    let result = VerifyResult {
        signature_valid: verification.signature_valid,
        nonce_matches: verification.nonce_matches,
        pcr_results: verification
            .pcr_matches
            .iter()
            .map(|m| PcrVerifyEntry {
                index: m.index,
                bank: m.bank.clone(),
                matches: m.matches,
            })
            .collect(),
        verified: verification.verified,
        measurement,
    };

    println!("{}", render(&result, format));

    if !verification.verified {
        eprintln!();
        let diag = tpm_core::diag::Diagnostic::warning(
            tpm_core::diag::DiagCode::E0600,
            "quote verification failed",
        );
        if !verification.signature_valid {
            eprintln!(
                "{}",
                diag.clone()
                    .with_cause("signature does not match AK public key")
                    .render_text()
            );
        }
        if !verification.nonce_matches {
            eprintln!(
                "{}",
                diag.clone()
                    .with_cause("nonce mismatch — possible replay")
                    .render_text()
            );
        }
        for m in &verification.pcr_matches {
            if !m.matches {
                eprintln!(
                    "  PCR {}:{} — expected {} got {}",
                    m.bank, m.index, m.expected, m.actual
                );
            }
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct VerifyResult {
    signature_valid: bool,
    nonce_matches: bool,
    pcr_results: Vec<PcrVerifyEntry>,
    verified: bool,
    measurement: Option<MeasurementVerify>,
}

#[derive(Serialize)]
struct PcrVerifyEntry {
    index: u32,
    bank: String,
    matches: bool,
}

#[derive(Serialize)]
struct MeasurementVerify {
    stream: String,
    segment_id: u64,
    merkle_root: String,
    seq_range: String,
    signer_identity: Option<String>,
    checkpoint_chain_ok: bool,
    error: Option<String>,
}

impl TextRenderable for VerifyResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("quote verification\n");
        out.push_str(&format!(
            "  signature: {}\n",
            if self.signature_valid {
                "valid"
            } else {
                "INVALID"
            }
        ));
        out.push_str(&format!(
            "  nonce:     {}\n",
            if self.nonce_matches {
                "matches"
            } else {
                "MISMATCH"
            }
        ));
        for pcr in &self.pcr_results {
            let status = if pcr.matches { "ok" } else { "MISMATCH" };
            out.push_str(&format!(
                "  PCR {}:{}  {}\n",
                pcr.bank, pcr.index, status
            ));
        }
        if let Some(m) = &self.measurement {
            out.push_str("\n  measurement checkpoint:\n");
            out.push_str(&format!("    stream:    {}\n", m.stream));
            out.push_str(&format!("    segment:   {} {}\n", m.segment_id, m.seq_range));
            out.push_str(&format!("    root:      {}\n", m.merkle_root));
            if let Some(id) = &m.signer_identity {
                out.push_str(&format!("    signer:    {}\n", id));
            }
            out.push_str(&format!(
                "    checkpoint signature: {}\n",
                if m.checkpoint_chain_ok { "VERIFIED" } else { "FAILED" }
            ));
            if let Some(e) = &m.error {
                out.push_str(&format!("    error:     {}\n", e));
            }
        }
        out.push_str(&format!(
            "\n  result: {}\n",
            if self.verified {
                "VERIFIED"
            } else {
                "FAILED"
            }
        ));
        out
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
