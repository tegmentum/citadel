use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::{Deserialize, Serialize};

// -- workspace export --

pub fn export(
    store: &Store,
    output: &std::path::Path,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    let profiles = store.list_profiles()?;
    let baselines = store.list_pcr_baselines()?;
    let nv_indices = store.list_nv_indices()?;

    let snapshot = WorkspaceSnapshot {
        version: 1,
        objects: objects
            .iter()
            .map(|o| ExportedObject {
                path: o.path.to_string(),
                kind: format!("{:?}", o.kind),
                algorithm: o.algorithm.to_string(),
                has_policy: o.policy_id.is_some(),
                created_at: o.created_at.to_rfc3339(),
            })
            .collect(),
        policies: policies
            .iter()
            .map(|p| ExportedPolicy {
                name: p.name.clone(),
                rule_count: p.rules.len(),
            })
            .collect(),
        profiles: profiles
            .iter()
            .map(|p| ExportedProfile {
                name: p.name.clone(),
                default_algorithm: p.default_algorithm.to_string(),
                active: p.is_active,
            })
            .collect(),
        pcr_baselines: baselines,
        nv_indices: nv_indices
            .iter()
            .map(|(name, idx, size)| ExportedNv {
                name: name.clone(),
                index: format!("0x{:08X}", idx),
                size: *size,
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&snapshot)?;
    std::fs::write(output, &json)?;

    let result = ExportResult {
        path: output.display().to_string(),
        objects: snapshot.objects.len(),
        policies: snapshot.policies.len(),
        profiles: snapshot.profiles.len(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

// -- workspace info --

pub fn info(store: &Store, store_path: &std::path::Path, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    let profiles = store.list_profiles()?;
    let active = store.get_active_profile()?;
    let baselines = store.list_pcr_baselines()?;
    let nv_indices = store.list_nv_indices()?;

    let result = WorkspaceInfo {
        store_path: store_path.display().to_string(),
        objects: objects.len(),
        policies: policies.len(),
        profiles: profiles.len(),
        active_profile: active.map(|p| p.name),
        pcr_baselines: baselines.len(),
        nv_indices: nv_indices.len(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

// -- Types --

#[derive(Serialize, Deserialize)]
struct WorkspaceSnapshot {
    version: u32,
    objects: Vec<ExportedObject>,
    policies: Vec<ExportedPolicy>,
    profiles: Vec<ExportedProfile>,
    pcr_baselines: Vec<String>,
    nv_indices: Vec<ExportedNv>,
}

#[derive(Serialize, Deserialize)]
struct ExportedObject {
    path: String,
    kind: String,
    algorithm: String,
    has_policy: bool,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct ExportedPolicy {
    name: String,
    rule_count: usize,
}

#[derive(Serialize, Deserialize)]
struct ExportedProfile {
    name: String,
    default_algorithm: String,
    active: bool,
}

#[derive(Serialize, Deserialize)]
struct ExportedNv {
    name: String,
    index: String,
    size: usize,
}

#[derive(Serialize)]
struct ExportResult {
    path: String,
    objects: usize,
    policies: usize,
    profiles: usize,
}

impl TextRenderable for ExportResult {
    fn render_text(&self) -> String {
        format!(
            "workspace exported to: {}\n  objects:  {}\n  policies: {}\n  profiles: {}\n",
            self.path, self.objects, self.policies, self.profiles
        )
    }
}

#[derive(Serialize)]
struct WorkspaceInfo {
    store_path: String,
    objects: usize,
    policies: usize,
    profiles: usize,
    active_profile: Option<String>,
    pcr_baselines: usize,
    nv_indices: usize,
}

impl TextRenderable for WorkspaceInfo {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("store:      {}\n", self.store_path));
        out.push_str(&format!("objects:    {}\n", self.objects));
        out.push_str(&format!("policies:   {}\n", self.policies));
        out.push_str(&format!("profiles:   {}\n", self.profiles));
        out.push_str(&format!(
            "active:     {}\n",
            self.active_profile.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!("baselines:  {}\n", self.pcr_baselines));
        out.push_str(&format!("NV indices: {}\n", self.nv_indices));
        out
    }
}
