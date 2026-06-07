use tpm_core::backend::TpmBackend;
use tpm_core::diag::{DiagCode, Diagnostic};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- repair scan --

pub fn scan(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let issues = detect_issues(store, backend)?;

    let report = ScanReport {
        issue_count: issues.len(),
        issues: issues
            .iter()
            .map(|i| IssueSummary {
                severity: i.severity.clone(),
                code: i.code.clone(),
                message: i.message.clone(),
                object: i.object.clone(),
                remediation: i.remediation.clone(),
            })
            .collect(),
    };

    println!("{}", render(&report, format));

    if !issues.is_empty() {
        eprintln!();
        let diag = Diagnostic::warning(
            DiagCode::E0006,
            format!("{} issue(s) detected", issues.len()),
        )
        .with_suggestion("run `tpm repair plan` to see proposed fixes")
        .with_suggestion("run `tpm repair apply` to fix automatically");
        eprintln!("{}", diag.render_text());
    }

    Ok(())
}

// -- repair plan --

pub fn plan(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let issues = detect_issues(store, backend)?;

    if issues.is_empty() {
        println!("No issues found. Workspace is healthy.");
        return Ok(());
    }

    let plan = RepairPlan {
        steps: issues
            .iter()
            .enumerate()
            .map(|(i, issue)| RepairStep {
                step: i + 1,
                action: issue.remediation.clone(),
                target: issue.object.clone(),
                severity: issue.severity.clone(),
                reversible: issue.reversible,
            })
            .collect(),
    };

    println!("{}", render(&plan, format));
    Ok(())
}

// -- repair apply --

pub fn apply(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let issues = detect_issues(store, backend)?;

    if issues.is_empty() {
        println!("No issues found. Nothing to repair.");
        return Ok(());
    }

    let mut fixed = 0;
    let mut skipped = 0;

    for issue in &issues {
        match issue.fix_action {
            FixAction::RemoveOrphanMetadata { ref path } => {
                let obj_path = tpm_core::model::ObjectPath::new(path)?;
                store.delete_object(&obj_path)?;
                store.log_action(
                    "repair.remove_orphan",
                    Some(path),
                    &serde_json::json!({"reason": &issue.message}),
                )?;
                fixed += 1;
            }
            FixAction::RemoveOrphanNv { ref name } => {
                store.delete_nv_index(name)?;
                store.log_action(
                    "repair.remove_orphan_nv",
                    None,
                    &serde_json::json!({"name": name}),
                )?;
                fixed += 1;
            }
            FixAction::MarkDrifted { ref path } => {
                store.log_action(
                    "repair.mark_drifted",
                    Some(path),
                    &serde_json::json!({"reason": &issue.message}),
                )?;
                fixed += 1;
            }
            FixAction::NoAutoFix => {
                skipped += 1;
            }
        }
    }

    let result = RepairResult {
        total: issues.len(),
        fixed,
        skipped,
    };

    println!("{}", render(&result, format));
    Ok(())
}

// -- Detection engine --

struct Issue {
    severity: String,
    code: String,
    message: String,
    object: Option<String>,
    remediation: String,
    reversible: bool,
    fix_action: FixAction,
}

#[allow(dead_code)]
enum FixAction {
    RemoveOrphanMetadata { path: String },
    RemoveOrphanNv { name: String },
    MarkDrifted { path: String },
    NoAutoFix,
}

fn detect_issues(store: &Store, backend: &dyn TpmBackend) -> anyhow::Result<Vec<Issue>> {
    let mut issues = Vec::new();

    // Check 1: backend reachable
    match backend.status() {
        Ok(status) if !status.available => {
            issues.push(Issue {
                severity: "error".to_string(),
                code: "REPAIR001".to_string(),
                message: "TPM backend is not available".to_string(),
                object: None,
                remediation: "check TPM device and TCTI configuration".to_string(),
                reversible: false,
                fix_action: FixAction::NoAutoFix,
            });
        }
        Err(e) => {
            issues.push(Issue {
                severity: "error".to_string(),
                code: "REPAIR001".to_string(),
                message: format!("cannot reach TPM backend: {}", e),
                object: None,
                remediation: "check TPM device and TCTI configuration".to_string(),
                reversible: false,
                fix_action: FixAction::NoAutoFix,
            });
        }
        _ => {}
    }

    // Check 2: objects with missing handle blobs
    let objects = store.list_objects()?;
    for obj in &objects {
        if obj.handle_blob.is_none()
            && matches!(
                obj.kind,
                tpm_core::model::ObjectKind::SigningKey
                    | tpm_core::model::ObjectKind::StorageKey
                    | tpm_core::model::ObjectKind::AttestationKey
            )
        {
            issues.push(Issue {
                severity: "warning".to_string(),
                code: "REPAIR002".to_string(),
                message: format!("key '{}' has no handle blob", obj.path),
                object: Some(obj.path.to_string()),
                remediation: "recreate the key or remove stale metadata".to_string(),
                reversible: true,
                fix_action: FixAction::RemoveOrphanMetadata {
                    path: obj.path.to_string(),
                },
            });
        }
    }

    // Check 3: objects referencing non-existent policies
    for obj in &objects {
        if let Some(policy_id) = obj.policy_id {
            if store.get_policy_by_id(&policy_id)?.is_none() {
                issues.push(Issue {
                    severity: "warning".to_string(),
                    code: "REPAIR003".to_string(),
                    message: format!(
                        "object '{}' references policy {} which no longer exists",
                        obj.path, policy_id
                    ),
                    object: Some(obj.path.to_string()),
                    remediation: "detach the policy reference or recreate the policy".to_string(),
                    reversible: false,
                    fix_action: FixAction::MarkDrifted {
                        path: obj.path.to_string(),
                    },
                });
            }
        }
    }

    // Check 4: no active profile
    if store.get_active_profile()?.is_none() && !store.list_profiles()?.is_empty() {
        issues.push(Issue {
            severity: "info".to_string(),
            code: "REPAIR004".to_string(),
            message: "no active profile set despite profiles existing".to_string(),
            object: None,
            remediation: "run `tpm profile set <name>` to activate a profile".to_string(),
            reversible: true,
            fix_action: FixAction::NoAutoFix,
        });
    }

    // Check 5: NV indices with no data
    let nv_indices = store.list_nv_indices()?;
    for (name, _idx, _size) in &nv_indices {
        if store.nv_read_data(name)?.is_none() {
            issues.push(Issue {
                severity: "info".to_string(),
                code: "REPAIR005".to_string(),
                message: format!("NV index '{}' is defined but has never been written", name),
                object: None,
                remediation: format!("write data with `tpm nv write {} --input <file>`", name),
                reversible: true,
                fix_action: FixAction::NoAutoFix,
            });
        }
    }

    // Check 6: orphan identities (identity references a key that doesn't exist)
    let identities = store.list_identities()?;
    for ident in &identities {
        let key_exists = objects.iter().any(|o| o.id == ident.key_object_id);
        if !key_exists {
            issues.push(Issue {
                severity: "error".to_string(),
                code: "REPAIR006".to_string(),
                message: format!(
                    "identity '{}' references missing key (id={})",
                    ident.name, ident.key_object_id
                ),
                object: Some(format!("identity:{}", ident.name)),
                remediation: format!(
                    "rotate with `tpm identity rotate {}` or delete with `tpm identity delete {}`",
                    ident.name, ident.name
                ),
                reversible: false,
                fix_action: FixAction::NoAutoFix,
            });
        }
    }

    // Check 7: fragile policies (PCR 0-7 boot-sensitive)
    for policy in store.list_policies()? {
        let report = tpm_core::service::rate_policy(&policy);
        if matches!(report.overall, tpm_core::service::FragilityRating::High) {
            issues.push(Issue {
                severity: "warning".to_string(),
                code: "REPAIR007".to_string(),
                message: format!(
                    "policy '{}' is fragile under expected boot events",
                    policy.name
                ),
                object: Some(format!("policy:{}", policy.name)),
                remediation: format!(
                    "run `tpm policy fragility {}` for details; consider using higher PCR indices",
                    policy.name
                ),
                reversible: true,
                fix_action: FixAction::NoAutoFix,
            });
        }
    }

    Ok(issues)
}

// -- Output types --

#[derive(Serialize)]
struct ScanReport {
    issue_count: usize,
    issues: Vec<IssueSummary>,
}

#[derive(Serialize)]
struct IssueSummary {
    severity: String,
    code: String,
    message: String,
    object: Option<String>,
    remediation: String,
}

impl TextRenderable for ScanReport {
    fn render_text(&self) -> String {
        if self.issues.is_empty() {
            return "Scan complete. No issues found.\n".to_string();
        }
        let mut out = String::new();
        out.push_str(&format!(
            "Scan complete. {} issue(s) found:\n\n",
            self.issue_count
        ));
        for issue in &self.issues {
            let icon = match issue.severity.as_str() {
                "error" => "ERR ",
                "warning" => "WARN",
                "info" => "INFO",
                _ => "    ",
            };
            out.push_str(&format!(
                "  [{}] [{}] {}\n",
                icon, issue.code, issue.message
            ));
            if let Some(ref obj) = issue.object {
                out.push_str(&format!("         object: {}\n", obj));
            }
            out.push_str(&format!("         fix: {}\n", issue.remediation));
            out.push('\n');
        }
        out
    }
}

#[derive(Serialize)]
struct RepairPlan {
    steps: Vec<RepairStep>,
}

#[derive(Serialize)]
struct RepairStep {
    step: usize,
    action: String,
    target: Option<String>,
    severity: String,
    reversible: bool,
}

impl TextRenderable for RepairPlan {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Repair plan ({} step(s)):\n\n", self.steps.len()));
        for step in &self.steps {
            out.push_str(&format!("  {}. {}\n", step.step, step.action));
            if let Some(ref target) = step.target {
                out.push_str(&format!("     target: {}\n", target));
            }
            out.push_str(&format!(
                "     reversible: {}\n",
                if step.reversible { "yes" } else { "no" }
            ));
            out.push('\n');
        }
        out
    }
}

#[derive(Serialize)]
struct RepairResult {
    total: usize,
    fixed: usize,
    skipped: usize,
}

impl TextRenderable for RepairResult {
    fn render_text(&self) -> String {
        format!(
            "Repair complete.\n  total:   {}\n  fixed:   {}\n  skipped: {}\n",
            self.total, self.fixed, self.skipped
        )
    }
}
