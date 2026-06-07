use tpm_core::backend::TpmBackend;
use tpm_core::model::Algorithm;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;

use serde::Serialize;

pub fn run(backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let status = backend.status()?;

    let caps = Capabilities {
        backend_type: status.backend_type,
        manufacturer: status.manufacturer,
        firmware_version: status.firmware_version,
        available: status.available,
        supported_algorithms: Algorithm::all().iter().map(|a| a.to_string()).collect(),
        pcr_banks: vec![
            "sha256".to_string(),
            "sha384".to_string(),
            "sha1".to_string(),
        ],
        max_nv_size: 2048,
        max_persistent_handles: 7,
    };

    println!("{}", render(&caps, format));
    Ok(())
}

pub fn debug_bundle(
    backend: &dyn TpmBackend,
    store: &tpm_core::store::Store,
    store_path: &std::path::Path,
    output: &std::path::Path,
) -> anyhow::Result<()> {
    let status = backend.status().ok();
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    let profiles = store.list_profiles()?;
    let log = store.list_audit_log(None, None, 50)?;

    let bundle = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "store_path": store_path.display().to_string(),
        "backend": status,
        "object_count": objects.len(),
        "objects": objects.iter().map(|o| serde_json::json!({
            "path": o.path.to_string(),
            "kind": o.kind.to_string(),
            "algorithm": o.algorithm.to_string(),
            "has_handle": o.handle_blob.is_some(),
            "has_policy": o.policy_id.is_some(),
        })).collect::<Vec<_>>(),
        "policy_count": policies.len(),
        "policies": policies.iter().map(|p| serde_json::json!({
            "name": p.name,
            "rule_count": p.rules.len(),
        })).collect::<Vec<_>>(),
        "profile_count": profiles.len(),
        "profiles": profiles.iter().map(|p| serde_json::json!({
            "name": p.name,
            "active": p.is_active,
        })).collect::<Vec<_>>(),
        "recent_log": log,
    });

    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(output, &json)?;
    println!("debug bundle written to: {}", output.display());
    println!("  objects:  {}", objects.len());
    println!("  policies: {}", policies.len());
    println!("  log:      {} entries", log.len());
    Ok(())
}

#[derive(Serialize)]
struct Capabilities {
    backend_type: String,
    manufacturer: String,
    firmware_version: String,
    available: bool,
    supported_algorithms: Vec<String>,
    pcr_banks: Vec<String>,
    max_nv_size: usize,
    max_persistent_handles: usize,
}

impl TextRenderable for Capabilities {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("TPM Capabilities\n\n");
        out.push_str(&format!("  backend:     {}\n", self.backend_type));
        out.push_str(&format!("  manufacturer: {}\n", self.manufacturer));
        out.push_str(&format!("  firmware:     {}\n", self.firmware_version));
        out.push_str(&format!(
            "  available:    {}\n",
            if self.available { "yes" } else { "no" }
        ));
        out.push_str("\n  algorithms:\n");
        for alg in &self.supported_algorithms {
            out.push_str(&format!("    - {}\n", alg));
        }
        out.push_str("\n  PCR banks:\n");
        for bank in &self.pcr_banks {
            out.push_str(&format!("    - {}\n", bank));
        }
        out.push_str(&format!(
            "\n  max NV size:          {} bytes\n",
            self.max_nv_size
        ));
        out.push_str(&format!(
            "  max persistent handles: {}\n",
            self.max_persistent_handles
        ));
        out
    }
}
