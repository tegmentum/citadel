//! Declarative manifest commands: apply, diff, plan.

use tpm_core::backend::TpmBackend;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::policy::Manifest;
use tpm_core::service::ApplyReport;
use tpm_core::store::Store;

use serde::Serialize;

fn load_manifest(file: &std::path::Path) -> anyhow::Result<Manifest> {
    let text = std::fs::read_to_string(file)?;
    let manifest = Manifest::from_yaml(&text)
        .map_err(|e| anyhow::anyhow!("manifest parse error in {}: {}", file.display(), e))?;

    let issues = manifest.validate();
    if !issues.is_empty() {
        eprintln!("manifest validation errors in {}:", file.display());
        for issue in &issues {
            eprintln!("  {}", issue);
        }
        anyhow::bail!("{} validation error(s)", issues.len());
    }

    Ok(manifest)
}

pub fn apply_cmd(
    store: &Store,
    backend: &dyn TpmBackend,
    file: &std::path::Path,
    force: bool,
    plan_mode: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let manifest = load_manifest(file)?;

    if plan_mode {
        let actions = tpm_core::service::diff_manifest(store, &manifest)?;
        crate::plan::show_plan(&actions);
        return Ok(());
    }

    let report = tpm_core::service::apply_manifest(store, backend, &manifest, force)?;

    let out = ApplyOutput::from(&report);
    println!("{}", render(&out, format));
    Ok(())
}

pub fn diff_cmd(store: &Store, file: &std::path::Path, format: OutputFormat) -> anyhow::Result<()> {
    let manifest = load_manifest(file)?;
    let actions = tpm_core::service::diff_manifest(store, &manifest)?;

    let out = DiffOutput {
        manifest: file.display().to_string(),
        action_count: actions.len(),
        actions: actions
            .iter()
            .map(|a| ActionSummary {
                action: a.action.clone(),
                target: a.target.clone(),
                risk: a.risk.to_string(),
                reversible: a.reversible,
            })
            .collect(),
    };

    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct ApplyOutput {
    correlation_id: String,
    created: Vec<String>,
    updated: Vec<String>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

impl From<&ApplyReport> for ApplyOutput {
    fn from(r: &ApplyReport) -> Self {
        Self {
            correlation_id: r.correlation_id.clone(),
            created: r.created.clone(),
            updated: r.updated.clone(),
            warnings: r.warnings.clone(),
            errors: r.errors.clone(),
        }
    }
}

impl TextRenderable for ApplyOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "apply complete (correlation_id: {})\n\n",
            self.correlation_id
        ));
        if !self.created.is_empty() {
            out.push_str("created:\n");
            for c in &self.created {
                out.push_str(&format!("  + {}\n", c));
            }
        }
        if !self.updated.is_empty() {
            out.push_str("updated:\n");
            for u in &self.updated {
                out.push_str(&format!("  ~ {}\n", u));
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("\nwarnings:\n");
            for w in &self.warnings {
                out.push_str(&format!("  ! {}\n", w));
            }
        }
        if !self.errors.is_empty() {
            out.push_str("\nerrors:\n");
            for e in &self.errors {
                out.push_str(&format!("  x {}\n", e));
            }
        }
        if self.created.is_empty()
            && self.updated.is_empty()
            && self.warnings.is_empty()
            && self.errors.is_empty()
        {
            out.push_str("no changes (workspace matches manifest)\n");
        }
        out
    }
}

#[derive(Serialize)]
struct DiffOutput {
    manifest: String,
    action_count: usize,
    actions: Vec<ActionSummary>,
}

#[derive(Serialize)]
struct ActionSummary {
    action: String,
    target: Option<String>,
    risk: String,
    reversible: bool,
}

impl TextRenderable for DiffOutput {
    fn render_text(&self) -> String {
        if self.actions.is_empty() {
            return format!("no drift (workspace matches manifest {})\n", self.manifest);
        }
        let mut out = String::new();
        out.push_str(&format!(
            "diff: {} action(s) required to match {}\n\n",
            self.action_count, self.manifest
        ));
        for a in &self.actions {
            out.push_str(&format!("  - {}\n", a.action));
            if let Some(ref t) = a.target {
                out.push_str(&format!("    target: {}\n", t));
            }
            out.push_str(&format!(
                "    risk: {}  reversible: {}\n",
                a.risk,
                if a.reversible { "yes" } else { "no" }
            ));
        }
        out
    }
}
