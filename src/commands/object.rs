use tpm_core::model::{ObjectKind, ObjectPath};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- object list --

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;

    let listing = ObjectListing {
        objects: objects
            .iter()
            .map(|o| ObjectSummary {
                path: o.path.to_string(),
                kind: o.kind.to_string(),
                algorithm: o.algorithm.to_string(),
                has_policy: o.policy_id.is_some(),
                created_at: o.created_at.to_rfc3339(),
            })
            .collect(),
    };

    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct ObjectListing {
    objects: Vec<ObjectSummary>,
}

#[derive(Serialize)]
struct ObjectSummary {
    path: String,
    kind: String,
    algorithm: String,
    has_policy: bool,
    created_at: String,
}

impl TextRenderable for ObjectListing {
    fn render_text(&self) -> String {
        if self.objects.is_empty() {
            return "No objects in workspace.\n".to_string();
        }
        let max_path = self.objects.iter().map(|o| o.path.len()).max().unwrap_or(10);
        let max_kind = self
            .objects
            .iter()
            .map(|o| o.kind.len())
            .max()
            .unwrap_or(10);

        let mut out = String::new();
        out.push_str(&format!(
            "{:<pw$}  {:<kw$}  {:<15}  {:<8}  {}\n",
            "PATH",
            "KIND",
            "ALGORITHM",
            "POLICY",
            "CREATED",
            pw = max_path,
            kw = max_kind
        ));
        for obj in &self.objects {
            out.push_str(&format!(
                "{:<pw$}  {:<kw$}  {:<15}  {:<8}  {}\n",
                obj.path,
                obj.kind,
                obj.algorithm,
                if obj.has_policy { "yes" } else { "no" },
                &obj.created_at[..19],
                pw = max_path,
                kw = max_kind
            ));
        }
        out
    }
}

// -- object tree --

pub fn tree(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;

    let tree = ObjectTree {
        keys: objects
            .iter()
            .filter(|o| {
                matches!(
                    o.kind,
                    tpm_core::model::ObjectKind::SigningKey
                        | tpm_core::model::ObjectKind::StorageKey
                        | tpm_core::model::ObjectKind::AttestationKey
                )
            })
            .map(|o| o.path.to_string())
            .collect(),
        secrets: objects
            .iter()
            .filter(|o| matches!(o.kind, tpm_core::model::ObjectKind::SealedBlob))
            .map(|o| o.path.to_string())
            .collect(),
        nv_indices: objects
            .iter()
            .filter(|o| matches!(o.kind, tpm_core::model::ObjectKind::NvIndex))
            .map(|o| o.path.to_string())
            .collect(),
        policies: policies.iter().map(|p| p.name.clone()).collect(),
    };

    println!("{}", render(&tree, format));
    Ok(())
}

#[derive(Serialize)]
struct ObjectTree {
    keys: Vec<String>,
    secrets: Vec<String>,
    nv_indices: Vec<String>,
    policies: Vec<String>,
}

impl TextRenderable for ObjectTree {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("workspace\n");

        if !self.keys.is_empty() {
            out.push_str("  keys/\n");
            for (i, k) in self.keys.iter().enumerate() {
                let connector = if i == self.keys.len() - 1 {
                    "└──"
                } else {
                    "├──"
                };
                out.push_str(&format!("    {} {}\n", connector, k));
            }
        }

        if !self.secrets.is_empty() {
            out.push_str("  secrets/\n");
            for (i, s) in self.secrets.iter().enumerate() {
                let connector = if i == self.secrets.len() - 1 {
                    "└──"
                } else {
                    "├──"
                };
                out.push_str(&format!("    {} {}\n", connector, s));
            }
        }

        if !self.nv_indices.is_empty() {
            out.push_str("  nv/\n");
            for (i, n) in self.nv_indices.iter().enumerate() {
                let connector = if i == self.nv_indices.len() - 1 {
                    "└──"
                } else {
                    "├──"
                };
                out.push_str(&format!("    {} {}\n", connector, n));
            }
        }

        if !self.policies.is_empty() {
            out.push_str("  policies/\n");
            for (i, p) in self.policies.iter().enumerate() {
                let connector = if i == self.policies.len() - 1 {
                    "└──"
                } else {
                    "├──"
                };
                out.push_str(&format!("    {} {}\n", connector, p));
            }
        }

        if self.keys.is_empty()
            && self.secrets.is_empty()
            && self.nv_indices.is_empty()
            && self.policies.is_empty()
        {
            out.push_str("  (empty)\n");
        }

        out
    }
}

// -- object dependents --

pub fn dependents(store: &Store, path_str: &str, format: OutputFormat) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;

    let target = store
        .get_object(&path)?
        .ok_or_else(|| anyhow::anyhow!("object not found: {}", path_str))?;

    let all_objects = store.list_objects()?;

    // Find objects sharing the same policy
    let mut shared_policy = Vec::new();
    if let Some(target_policy_id) = target.policy_id {
        for obj in &all_objects {
            if obj.path != target.path && obj.policy_id == Some(target_policy_id) {
                shared_policy.push(obj.path.to_string());
            }
        }
    }

    // Find attached policies
    let policies = store.list_policies()?;
    let attached_policies: Vec<String> = policies
        .iter()
        .filter(|p| target.policy_id.map(|id| id == p.id).unwrap_or(false))
        .map(|p| p.name.clone())
        .collect();

    // Check for rotation history
    let rotation_history: Vec<String> = all_objects
        .iter()
        .filter(|o| {
            o.metadata
                .get("rotated_from")
                .and_then(|v| v.as_str())
                .map(|s| s == path_str)
                .unwrap_or(false)
        })
        .map(|o| o.path.to_string())
        .collect();

    let result = DependentsResult {
        path: path_str.to_string(),
        kind: target.kind.to_string(),
        shared_policy,
        attached_policies,
        rotation_history,
    };

    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct DependentsResult {
    path: String,
    kind: String,
    shared_policy: Vec<String>,
    attached_policies: Vec<String>,
    rotation_history: Vec<String>,
}

impl TextRenderable for DependentsResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("dependents of: {} ({})\n\n", self.path, self.kind));

        if !self.attached_policies.is_empty() {
            out.push_str("  attached policies:\n");
            for p in &self.attached_policies {
                out.push_str(&format!("    - {}\n", p));
            }
        }

        if !self.shared_policy.is_empty() {
            out.push_str("  objects sharing same policy:\n");
            for o in &self.shared_policy {
                out.push_str(&format!("    - {}\n", o));
            }
        }

        if !self.rotation_history.is_empty() {
            out.push_str("  rotated predecessors:\n");
            for r in &self.rotation_history {
                out.push_str(&format!("    - {}\n", r));
            }
        }

        if self.attached_policies.is_empty()
            && self.shared_policy.is_empty()
            && self.rotation_history.is_empty()
        {
            out.push_str("  no dependents found\n");
        }

        out
    }
}

// -- object rename --

pub fn rename(
    store: &Store,
    old_path_str: &str,
    new_path_str: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let old_path = ObjectPath::new(old_path_str)?;
    let new_path = ObjectPath::new(new_path_str)?;

    if store.get_object(&old_path)?.is_none() {
        anyhow::bail!("object not found: {}", old_path_str);
    }
    if store.get_object(&new_path)?.is_some() {
        anyhow::bail!("target name already exists: {}", new_path_str);
    }

    store.rename_object(&old_path, &new_path)?;
    store.log_action(
        "object.rename",
        Some(new_path_str),
        &serde_json::json!({"from": old_path_str, "to": new_path_str}),
    )?;

    let result = RenameResult {
        from: old_path_str.to_string(),
        to: new_path_str.to_string(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct RenameResult {
    from: String,
    to: String,
}

impl TextRenderable for RenameResult {
    fn render_text(&self) -> String {
        format!("renamed: {} -> {}\n", self.from, self.to)
    }
}

// -- gc (garbage collection) --

pub fn gc_plan(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let mut candidates = Vec::new();

    for obj in &objects {
        // Rotated keys are GC candidates
        if obj
            .metadata
            .get("rotated_from")
            .and_then(|v| v.as_str())
            .is_some()
        {
            candidates.push(GcCandidate {
                path: obj.path.to_string(),
                kind: obj.kind.to_string(),
                reason: "rotated predecessor (archived key)".to_string(),
            });
        }

        // Keys without handles are candidates
        if matches!(
            obj.kind,
            ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
        ) && obj.handle_blob.is_none()
        {
            candidates.push(GcCandidate {
                path: obj.path.to_string(),
                kind: obj.kind.to_string(),
                reason: "key has no handle blob (orphaned metadata)".to_string(),
            });
        }
    }

    let plan = GcPlan {
        candidate_count: candidates.len(),
        candidates,
    };
    println!("{}", render(&plan, format));
    Ok(())
}

pub fn gc_apply(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let mut removed = 0;

    for obj in &objects {
        let should_gc = obj
            .metadata
            .get("rotated_from")
            .and_then(|v| v.as_str())
            .is_some();

        if should_gc {
            store.delete_object(&obj.path)?;
            store.log_action(
                "gc.remove",
                Some(obj.path.as_str()),
                &serde_json::json!({"reason": "rotated predecessor"}),
            )?;
            removed += 1;
        }
    }

    let result = GcResult { removed };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct GcCandidate {
    path: String,
    kind: String,
    reason: String,
}

#[derive(Serialize)]
struct GcPlan {
    candidate_count: usize,
    candidates: Vec<GcCandidate>,
}

impl TextRenderable for GcPlan {
    fn render_text(&self) -> String {
        if self.candidates.is_empty() {
            return "No garbage collection candidates found.\n".to_string();
        }
        let mut out = String::new();
        out.push_str(&format!(
            "GC plan: {} candidate(s) for removal\n\n",
            self.candidate_count
        ));
        for c in &self.candidates {
            out.push_str(&format!("  {} ({})\n", c.path, c.kind));
            out.push_str(&format!("    reason: {}\n", c.reason));
        }
        out
    }
}

#[derive(Serialize)]
struct GcResult {
    removed: usize,
}

impl TextRenderable for GcResult {
    fn render_text(&self) -> String {
        format!("GC complete: {} object(s) removed\n", self.removed)
    }
}
