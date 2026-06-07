use tpm_core::backend::TpmBackend;
use tpm_core::diag::{DiagCode, Diagnostic};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

#[derive(Serialize)]
struct DoctorReport {
    checks: Vec<Check>,
    healthy: bool,
}

#[derive(Serialize)]
struct Check {
    name: String,
    status: String,
    detail: Option<String>,
}

impl TextRenderable for DoctorReport {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Doctor Report\n\n");
        for check in &self.checks {
            let icon = match check.status.as_str() {
                "ok" => "ok",
                "fail" => "FAIL",
                _ => "??",
            };
            out.push_str(&format!("  [{}] {}", icon, check.name));
            if let Some(detail) = &check.detail {
                out.push_str(&format!(" - {}", detail));
            }
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&format!(
            "Overall: {}\n",
            if self.healthy {
                "healthy"
            } else {
                "issues found"
            }
        ));
        out
    }
}

pub fn run(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let mut checks = Vec::new();
    let mut healthy = true;

    // Check backend
    match backend.status() {
        Ok(status) if status.available => {
            checks.push(Check {
                name: "TPM backend reachable".to_string(),
                status: "ok".to_string(),
                detail: Some(format!("{} ({})", status.backend_type, status.manufacturer)),
            });
        }
        Ok(_) => {
            healthy = false;
            checks.push(Check {
                name: "TPM backend reachable".to_string(),
                status: "fail".to_string(),
                detail: Some("backend reports unavailable".to_string()),
            });
        }
        Err(e) => {
            healthy = false;
            checks.push(Check {
                name: "TPM backend reachable".to_string(),
                status: "fail".to_string(),
                detail: Some(e.to_string()),
            });
        }
    }

    // Check store
    match store.list_objects() {
        Ok(objects) => {
            checks.push(Check {
                name: "Metadata store accessible".to_string(),
                status: "ok".to_string(),
                detail: Some(format!("{} objects", objects.len())),
            });
        }
        Err(e) => {
            healthy = false;
            checks.push(Check {
                name: "Metadata store accessible".to_string(),
                status: "fail".to_string(),
                detail: Some(e.to_string()),
            });
        }
    }

    // Check active profile
    match store.get_active_profile() {
        Ok(Some(profile)) => {
            checks.push(Check {
                name: "Active profile".to_string(),
                status: "ok".to_string(),
                detail: Some(profile.name),
            });
        }
        Ok(None) => {
            checks.push(Check {
                name: "Active profile".to_string(),
                status: "ok".to_string(),
                detail: Some("(none set)".to_string()),
            });
        }
        Err(e) => {
            healthy = false;
            checks.push(Check {
                name: "Active profile".to_string(),
                status: "fail".to_string(),
                detail: Some(e.to_string()),
            });
        }
    }

    let report = DoctorReport { checks, healthy };
    println!("{}", render(&report, format));

    if !healthy {
        let diag = Diagnostic::warning(DiagCode::E0006, "some health checks failed")
            .with_suggestion("run `tpm doctor --verbose` for more details")
            .with_suggestion("run `tpm repair scan` to check for fixable issues");
        eprintln!("{}", diag.render_text());
    }

    Ok(())
}
