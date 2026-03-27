use tpm_core::backend::TpmBackend;
use tpm_core::model::ObjectKind;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

#[derive(Serialize)]
struct StatusReport {
    backend: BackendInfo,
    workspace: WorkspaceInfo,
    health: HealthScore,
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
    key_count: usize,
    secret_count: usize,
    policy_count: usize,
    active_profile: Option<String>,
}

#[derive(Serialize)]
pub struct HealthScore {
    pub posture: String,
    pub score: u8,
    pub issues: Vec<String>,
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
        out.push_str(&format!("  keys:     {}\n", self.workspace.key_count));
        out.push_str(&format!("  secrets:  {}\n", self.workspace.secret_count));
        out.push_str(&format!("  policies: {}\n", self.workspace.policy_count));
        out.push_str(&format!(
            "  profile:  {}\n",
            self.workspace
                .active_profile
                .as_deref()
                .unwrap_or("(none)")
        ));
        out.push('\n');
        out.push_str(&format!("Health: {} ({}/100)\n", self.health.posture, self.health.score));
        if !self.health.issues.is_empty() {
            for issue in &self.health.issues {
                out.push_str(&format!("  - {}\n", issue));
            }
        }
        out
    }
}

pub fn run(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let status = backend.status()?;
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    let active_profile = store.get_active_profile()?;

    let key_count = objects
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
            )
        })
        .count();
    let secret_count = objects
        .iter()
        .filter(|o| o.kind == ObjectKind::SealedBlob)
        .count();

    let health = compute_health(&status.available, &objects, &policies, &active_profile);

    let report = StatusReport {
        backend: BackendInfo {
            backend_type: status.backend_type,
            manufacturer: status.manufacturer,
            firmware_version: status.firmware_version,
            available: status.available,
        },
        workspace: WorkspaceInfo {
            object_count: objects.len(),
            key_count,
            secret_count,
            policy_count: policies.len(),
            active_profile: active_profile.map(|p| p.name),
        },
        health,
    };

    println!("{}", render(&report, format));
    Ok(())
}

pub fn compute_health(
    backend_available: &bool,
    objects: &[tpm_core::model::TpmObject],
    policies: &[tpm_core::model::Policy],
    active_profile: &Option<tpm_core::model::Profile>,
) -> HealthScore {
    let mut score: i32 = 100;
    let mut issues = Vec::new();

    if !backend_available {
        score -= 40;
        issues.push("TPM backend unavailable".to_string());
    }

    if active_profile.is_none() {
        score -= 10;
        issues.push("no active profile set".to_string());
    }

    // Check for keys without handles
    let orphan_keys = objects
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
            ) && o.handle_blob.is_none()
        })
        .count();
    if orphan_keys > 0 {
        score -= 15;
        issues.push(format!("{} key(s) missing handle blobs", orphan_keys));
    }

    // Check for objects with dangling policy references
    let dangling = objects
        .iter()
        .filter(|o| {
            o.policy_id.is_some()
                && !policies
                    .iter()
                    .any(|p| Some(p.id) == o.policy_id)
        })
        .count();
    if dangling > 0 {
        score -= 10;
        issues.push(format!(
            "{} object(s) reference deleted policies",
            dangling
        ));
    }

    let score = score.max(0) as u8;
    let posture = match score {
        90..=100 => "healthy",
        70..=89 => "degraded",
        40..=69 => "warning",
        _ => "critical",
    }
    .to_string();

    HealthScore {
        posture,
        score,
        issues,
    }
}
