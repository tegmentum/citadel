use tpm_core::backend::TpmBackend;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- nv define --

pub fn define(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    size: usize,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if store.get_nv_index(name)?.is_some() {
        anyhow::bail!("NV index already defined: {}", name);
    }

    // Auto-assign an NV index number starting from 0x01000001
    let existing = store.list_nv_indices()?;
    let next_index = existing
        .iter()
        .map(|(_, idx, _)| *idx)
        .max()
        .unwrap_or(0x01000000)
        + 1;

    backend.nv_define(next_index, size)?;
    store.insert_nv_index(name, next_index, size)?;
    store.log_action(
        "nv.define",
        None,
        &serde_json::json!({"name": name, "index": format!("0x{:08X}", next_index), "size": size}),
    )?;

    let result = NvDefined {
        name: name.to_string(),
        index: format!("0x{:08X}", next_index),
        size,
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct NvDefined {
    name: String,
    index: String,
    size: usize,
}

impl TextRenderable for NvDefined {
    fn render_text(&self) -> String {
        format!(
            "NV index defined: {}\n  index: {}\n  size:  {} bytes\n",
            self.name, self.index, self.size
        )
    }
}

// -- nv write --

pub fn write(
    store: &Store,
    _backend: &dyn TpmBackend,
    name: &str,
    input: &std::path::Path,
) -> anyhow::Result<()> {
    let (_index, size) = store
        .get_nv_index(name)?
        .ok_or_else(|| anyhow::anyhow!("NV index not found: {}", name))?;

    let data = std::fs::read(input)?;
    if data.len() > size {
        anyhow::bail!(
            "data ({} bytes) exceeds NV index size ({} bytes)",
            data.len(),
            size
        );
    }

    store.nv_write_data(name, &data)?;
    store.log_action(
        "nv.write",
        None,
        &serde_json::json!({"name": name, "bytes": data.len()}),
    )?;

    println!("written {} bytes to NV index: {}", data.len(), name);
    Ok(())
}

// -- nv read --

pub fn read(
    store: &Store,
    _backend: &dyn TpmBackend,
    name: &str,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let (index, _size) = store
        .get_nv_index(name)?
        .ok_or_else(|| anyhow::anyhow!("NV index not found: {}", name))?;

    let data = store
        .nv_read_data(name)?
        .ok_or_else(|| anyhow::anyhow!("NV index '{}' has not been written", name))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &data)?;
        println!("read {} bytes from NV index '{}' to {}", data.len(), name, out_path.display());
    } else {
        let result = NvReadResult {
            name: name.to_string(),
            index: format!("0x{:08X}", index),
            size: data.len(),
            content_hex: hex_encode(&data),
            content_utf8: String::from_utf8(data.clone()).ok(),
        };
        println!("{}", render(&result, format));
    }
    Ok(())
}

#[derive(Serialize)]
struct NvReadResult {
    name: String,
    index: String,
    size: usize,
    content_hex: String,
    content_utf8: Option<String>,
}

impl TextRenderable for NvReadResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("NV index: {} ({})\n", self.name, self.index));
        out.push_str(&format!("  size: {} bytes\n", self.size));
        if let Some(ref text) = self.content_utf8 {
            out.push_str(&format!("  text: {}\n", text));
        }
        out.push_str(&format!("  hex:  {}\n", self.content_hex));
        out
    }
}

// -- nv list --

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let indices = store.list_nv_indices()?;

    let listing = NvListing {
        indices: indices
            .iter()
            .map(|(name, idx, size)| NvSummary {
                name: name.clone(),
                index: format!("0x{:08X}", idx),
                size: *size,
            })
            .collect(),
    };
    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct NvListing {
    indices: Vec<NvSummary>,
}

#[derive(Serialize)]
struct NvSummary {
    name: String,
    index: String,
    size: usize,
}

impl TextRenderable for NvListing {
    fn render_text(&self) -> String {
        if self.indices.is_empty() {
            return "No NV indices defined.\n".to_string();
        }
        let max_name = self.indices.iter().map(|n| n.name.len()).max().unwrap_or(10);
        let mut out = String::new();
        out.push_str(&format!(
            "{:<nw$}  {:<14}  {}\n",
            "NAME",
            "INDEX",
            "SIZE",
            nw = max_name
        ));
        for nv in &self.indices {
            out.push_str(&format!(
                "{:<nw$}  {:<14}  {} B\n",
                nv.name,
                nv.index,
                nv.size,
                nw = max_name
            ));
        }
        out
    }
}

// -- nv delete --

pub fn delete(store: &Store, backend: &dyn TpmBackend, name: &str) -> anyhow::Result<()> {
    let (index, _size) = store
        .get_nv_index(name)?
        .ok_or_else(|| anyhow::anyhow!("NV index not found: {}", name))?;

    backend.nv_undefine(index)?;
    store.delete_nv_index(name)?;
    store.log_action("nv.delete", None, &serde_json::json!({"name": name}))?;

    println!("NV index deleted: {}", name);
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
