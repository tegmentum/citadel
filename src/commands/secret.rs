use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::TpmBackend;
use tpm_core::diag::{DiagCode, Diagnostic};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, TpmObject};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- secret seal --

pub fn seal(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    input: &std::path::Path,
    policy_name: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(name)?;

    if store.get_object(&path)?.is_some() {
        let diag = Diagnostic::error(DiagCode::E0007, format!("object already exists: {}", path))
            .with_suggestion(format!("run `tpm secret show {}` to inspect it", path))
            .with_suggestion("choose a different name");
        eprintln!("{}", diag.render_text());
        anyhow::bail!("object already exists: {}", path);
    }

    let data = std::fs::read(input)?;

    let policy_id = if let Some(pname) = policy_name {
        let policy = store
            .get_policy(pname)?
            .ok_or_else(|| anyhow::anyhow!("policy not found: {}", pname))?;
        Some(policy.id)
    } else {
        None
    };

    let policy_digest: Option<Vec<u8>> = policy_id.map(|id| id.as_bytes().to_vec());
    let sealed = backend.seal(&data, policy_digest.as_deref())?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SealedBlob,
        algorithm: Algorithm::EccP256,
        policy_id,
        handle_blob: Some(serde_json::to_vec(&sealed)?),
        created_at: Utc::now(),
        metadata: serde_json::json!({
            "original_size": data.len(),
            "input": input.display().to_string(),
        }),
    };

    store.insert_object(&obj)?;
    store.log_action(
        "secret.seal",
        Some(path.as_str()),
        &serde_json::json!({"size": data.len()}),
    )?;

    let result = SealResult {
        path: path.to_string(),
        id: obj.id.to_string(),
        size: data.len(),
        has_policy: policy_id.is_some(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct SealResult {
    path: String,
    id: String,
    size: usize,
    has_policy: bool,
}

impl TextRenderable for SealResult {
    fn render_text(&self) -> String {
        format!(
            "secret sealed: {}\n  id: {}\n  size: {} bytes\n  policy: {}\n",
            self.path,
            self.id,
            self.size,
            if self.has_policy { "yes" } else { "none" }
        )
    }
}

// -- secret unseal --

pub fn unseal(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(name)?;

    let obj = store.get_object(&path)?.ok_or_else(|| {
        let diag = Diagnostic::error(DiagCode::E0004, format!("secret not found: {}", name))
            .with_suggestion("run `tpm secret list` to see available secrets");
        eprintln!("{}", diag.render_text());
        anyhow::anyhow!("secret not found: {}", name)
    })?;

    if obj.kind != ObjectKind::SealedBlob {
        anyhow::bail!("object '{}' is not a sealed secret (it is a {})", name, obj.kind);
    }

    let blob = obj
        .handle_blob
        .ok_or_else(|| anyhow::anyhow!("sealed blob missing for: {}", name))?;

    let sealed: tpm_core::backend::SealedData = serde_json::from_slice(&blob)?;
    let plaintext = backend.unseal(&sealed)?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &plaintext)?;
    }

    store.log_action("secret.unseal", Some(path.as_str()), &serde_json::json!({}))?;

    let result = UnsealResult {
        path: path.to_string(),
        size: plaintext.len(),
        output_file: output.map(|p| p.display().to_string()),
        data_preview: if output.is_none() {
            String::from_utf8(plaintext.clone())
                .ok()
                .map(|s| {
                    if s.len() > 200 {
                        format!("{}...", &s[..200])
                    } else {
                        s
                    }
                })
        } else {
            None
        },
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct UnsealResult {
    path: String,
    size: usize,
    output_file: Option<String>,
    data_preview: Option<String>,
}

impl TextRenderable for UnsealResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("unsealed: {}\n", self.path));
        out.push_str(&format!("  size: {} bytes\n", self.size));
        if let Some(f) = &self.output_file {
            out.push_str(&format!("  written to: {}\n", f));
        }
        if let Some(preview) = &self.data_preview {
            out.push_str(&format!("  content: {}\n", preview));
        }
        out
    }
}

// -- secret list --

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let secrets: Vec<_> = objects
        .into_iter()
        .filter(|o| o.kind == ObjectKind::SealedBlob)
        .collect();

    let listing = SecretListing {
        secrets: secrets
            .iter()
            .map(|s| {
                let size = s.metadata.get("original_size").and_then(|v| v.as_u64());
                SecretSummary {
                    path: s.path.to_string(),
                    size: size.map(|s| s as usize),
                    has_policy: s.policy_id.is_some(),
                    created_at: s.created_at.to_rfc3339(),
                }
            })
            .collect(),
    };
    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct SecretListing {
    secrets: Vec<SecretSummary>,
}

#[derive(Serialize)]
struct SecretSummary {
    path: String,
    size: Option<usize>,
    has_policy: bool,
    created_at: String,
}

impl TextRenderable for SecretListing {
    fn render_text(&self) -> String {
        if self.secrets.is_empty() {
            return "No sealed secrets.\n".to_string();
        }
        let max_path = self.secrets.iter().map(|s| s.path.len()).max().unwrap_or(10);
        let mut out = String::new();
        out.push_str(&format!(
            "{:<pw$}  {:<10}  {:<8}  {}\n",
            "PATH",
            "SIZE",
            "POLICY",
            "CREATED",
            pw = max_path
        ));
        for s in &self.secrets {
            out.push_str(&format!(
                "{:<pw$}  {:<10}  {:<8}  {}\n",
                s.path,
                s.size.map(|sz| format!("{} B", sz)).unwrap_or_else(|| "?".to_string()),
                if s.has_policy { "yes" } else { "no" },
                &s.created_at[..19],
                pw = max_path
            ));
        }
        out
    }
}
