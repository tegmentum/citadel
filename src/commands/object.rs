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
