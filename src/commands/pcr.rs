use tpm_core::backend::TpmBackend;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- pcr show --

pub fn show(
    backend: &dyn TpmBackend,
    bank: &str,
    indices: &[u32],
    format: OutputFormat,
) -> anyhow::Result<()> {
    let values = backend.pcr_read(bank, indices)?;

    let result = PcrShowResult {
        bank: bank.to_string(),
        values: values
            .iter()
            .map(|v| PcrEntry {
                index: v.index,
                digest: hex_encode(&v.digest),
            })
            .collect(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

// -- pcr extend --

pub fn extend(
    backend: &dyn TpmBackend,
    bank: &str,
    index: u32,
    input: Option<&std::path::Path>,
    value: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let digest = match (input, value) {
        (Some(path), None) => {
            let data = std::fs::read(path)?;
            tpm_core::backend::hash_for_bank(bank, &data)?
        }
        (None, Some(hex)) => hex_decode(hex)?,
        _ => anyhow::bail!("provide exactly one of --input <file> or --value <hex>"),
    };

    backend.pcr_extend(bank, index, &digest)?;
    let after = backend.pcr_read(bank, &[index])?;
    let new_value = after
        .first()
        .map(|v| hex_encode(&v.digest))
        .unwrap_or_default();

    let result = PcrExtendResult {
        bank: bank.to_string(),
        index,
        extended_with: hex_encode(&digest),
        new_value,
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct PcrExtendResult {
    bank: String,
    index: u32,
    extended_with: String,
    new_value: String,
}

impl TextRenderable for PcrExtendResult {
    fn render_text(&self) -> String {
        format!(
            "extended PCR {}[{}]\n  with:      {}\n  new value: {}\n",
            self.bank, self.index, self.extended_with, self.new_value
        )
    }
}

#[derive(Serialize)]
struct PcrShowResult {
    bank: String,
    values: Vec<PcrEntry>,
}

#[derive(Serialize)]
struct PcrEntry {
    index: u32,
    digest: String,
}

impl TextRenderable for PcrShowResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("PCR bank: {}\n\n", self.bank));
        for v in &self.values {
            out.push_str(&format!("  {:>2}  {}\n", v.index, v.digest));
        }
        out
    }
}

// -- pcr baseline save --

pub fn baseline_save(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    bank: &str,
    indices: &[u32],
    format: OutputFormat,
) -> anyhow::Result<()> {
    let values = backend.pcr_read(bank, indices)?;

    let values_json = serde_json::json!(
        values
            .iter()
            .map(|v| serde_json::json!({
                "index": v.index,
                "digest": hex_encode(&v.digest),
            }))
            .collect::<Vec<_>>()
    );

    store.save_pcr_baseline(name, bank, &values_json)?;
    store.log_action(
        "pcr.baseline.save",
        None,
        &serde_json::json!({"name": name, "bank": bank, "pcr_count": values.len()}),
    )?;

    let result = BaselineSaved {
        name: name.to_string(),
        bank: bank.to_string(),
        pcr_count: values.len(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct BaselineSaved {
    name: String,
    bank: String,
    pcr_count: usize,
}

impl TextRenderable for BaselineSaved {
    fn render_text(&self) -> String {
        format!(
            "baseline saved: {}\n  bank: {}\n  PCRs: {}\n",
            self.name, self.bank, self.pcr_count
        )
    }
}

// -- pcr baseline diff --

pub fn baseline_diff(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let (bank, saved_values) = store
        .get_pcr_baseline(name)?
        .ok_or_else(|| anyhow::anyhow!("baseline not found: {}", name))?;

    let saved_entries: Vec<serde_json::Value> = serde_json::from_value(saved_values)?;

    let indices: Vec<u32> = saved_entries
        .iter()
        .filter_map(|e| e.get("index").and_then(|i| i.as_u64()).map(|i| i as u32))
        .collect();

    let current = backend.pcr_read(&bank, &indices)?;

    let mut diffs = Vec::new();
    for (saved, current_val) in saved_entries.iter().zip(current.iter()) {
        let saved_digest = saved
            .get("digest")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let current_digest = hex_encode(&current_val.digest);
        let matches = saved_digest == current_digest;
        diffs.push(PcrDiffEntry {
            index: current_val.index,
            saved: saved_digest.to_string(),
            current: current_digest,
            matches,
        });
    }

    let all_match = diffs.iter().all(|d| d.matches);

    let result = PcrDiffResult {
        baseline: name.to_string(),
        bank: bank.clone(),
        diffs,
        all_match,
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct PcrDiffResult {
    baseline: String,
    bank: String,
    diffs: Vec<PcrDiffEntry>,
    all_match: bool,
}

#[derive(Serialize)]
struct PcrDiffEntry {
    index: u32,
    saved: String,
    current: String,
    matches: bool,
}

impl TextRenderable for PcrDiffResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "baseline: {} (bank: {})\n\n",
            self.baseline, self.bank
        ));
        for d in &self.diffs {
            let status = if d.matches { "  " } else { "!!" };
            out.push_str(&format!("  {} PCR {:>2}\n", status, d.index));
            if !d.matches {
                out.push_str(&format!("       saved:   {}\n", d.saved));
                out.push_str(&format!("       current: {}\n", d.current));
            }
        }
        out.push('\n');
        if self.all_match {
            out.push_str("result: all PCRs match baseline\n");
        } else {
            out.push_str("result: PCR MISMATCH detected\n");
        }
        out
    }
}

// -- pcr baseline list --

pub fn baseline_list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let baselines = store.list_pcr_baselines()?;

    let listing = BaselineListing {
        baselines: baselines.clone(),
    };
    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct BaselineListing {
    baselines: Vec<String>,
}

impl TextRenderable for BaselineListing {
    fn render_text(&self) -> String {
        if self.baselines.is_empty() {
            return "No PCR baselines saved.\n".to_string();
        }
        let mut out = String::new();
        for name in &self.baselines {
            out.push_str(&format!("  {}\n", name));
        }
        out
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex: {e}"))
        })
        .collect()
}
