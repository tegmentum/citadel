use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

pub fn list(
    store: &Store,
    filter_object: Option<&str>,
    filter_action: Option<&str>,
    limit: usize,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let entries = store.list_audit_log(filter_object, filter_action, limit)?;

    let listing = LogListing { entries };
    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct LogListing {
    entries: Vec<tpm_core::store::AuditEntry>,
}

impl TextRenderable for LogListing {
    fn render_text(&self) -> String {
        if self.entries.is_empty() {
            return "No audit log entries.\n".to_string();
        }
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&format!(
                "  {} {:>4}  {:<20}",
                &entry.timestamp[..19],
                entry.id,
                entry.action
            ));
            if let Some(ref path) = entry.object_path {
                out.push_str(&format!("  {}", path));
            }
            out.push('\n');
        }
        out
    }
}
