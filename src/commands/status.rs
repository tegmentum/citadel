use tpm_core::backend::TpmBackend;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

#[derive(Serialize)]
struct StatusReport {
    backend: BackendInfo,
    workspace: WorkspaceInfo,
}

#[derive(Serialize)]
struct BackendInfo {
    backend_type: String,
    manufacturer: String,
    firmware_version: String,
    available: bool,
}

#[derive(Serialize)]
struct WorkspaceInfo {
    object_count: usize,
    active_profile: Option<String>,
}

impl TextRenderable for StatusReport {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("TPM Status\n");
        out.push_str(&format!("  backend:      {}\n", self.backend.backend_type));
        out.push_str(&format!("  manufacturer: {}\n", self.backend.manufacturer));
        out.push_str(&format!("  firmware:     {}\n", self.backend.firmware_version));
        out.push_str(&format!(
            "  available:    {}\n",
            if self.backend.available { "yes" } else { "no" }
        ));
        out.push('\n');
        out.push_str("Workspace\n");
        out.push_str(&format!("  objects:  {}\n", self.workspace.object_count));
        out.push_str(&format!(
            "  profile:  {}\n",
            self.workspace
                .active_profile
                .as_deref()
                .unwrap_or("(none)")
        ));
        out
    }
}

pub fn run(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let status = backend.status()?;
    let objects = store.list_objects()?;
    let active_profile = store.get_active_profile()?;

    let report = StatusReport {
        backend: BackendInfo {
            backend_type: status.backend_type,
            manufacturer: status.manufacturer,
            firmware_version: status.firmware_version,
            available: status.available,
        },
        workspace: WorkspaceInfo {
            object_count: objects.len(),
            active_profile: active_profile.map(|p| p.name),
        },
    };

    println!("{}", render(&report, format));
    Ok(())
}
