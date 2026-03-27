use std::path::PathBuf;

use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::TpmBackend;
use tpm_core::diag::{DiagCode, Diagnostic};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, TpmObject};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- key create --

pub fn create(
    store: &Store,
    backend: &dyn TpmBackend,
    path_str: &str,
    algorithm_str: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str).map_err(|e| {
        let diag = Diagnostic::error(DiagCode::E0003, e.to_string());
        eprintln!("{}", diag.render_text());
        e
    })?;

    // Check if already exists
    if store.get_object(&path)?.is_some() {
        let diag = Diagnostic::error(
            DiagCode::E0007,
            format!("object already exists: {}", path),
        )
        .with_suggestion(format!("run `tpm key show {}` to inspect it", path))
        .with_suggestion("use a different name or delete the existing object first");
        eprintln!("{}", diag.render_text());
        anyhow::bail!("object already exists: {}", path);
    }

    let algorithm: Algorithm = algorithm_str.parse().map_err(|e: String| anyhow::anyhow!(e))?;

    let handle = backend.create_key(algorithm, &path)?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };

    store.insert_object(&obj)?;
    store.log_action(
        "key.create",
        Some(path.as_str()),
        &serde_json::json!({"algorithm": algorithm.to_string()}),
    )?;

    let summary = KeyCreated {
        path: path.to_string(),
        algorithm: algorithm.to_string(),
        id: obj.id.to_string(),
    };

    println!("{}", render(&summary, format));
    Ok(())
}

#[derive(Serialize)]
struct KeyCreated {
    path: String,
    algorithm: String,
    id: String,
}

impl TextRenderable for KeyCreated {
    fn render_text(&self) -> String {
        format!(
            "key created: {}\n  algorithm: {}\n  id: {}\n",
            self.path, self.algorithm, self.id
        )
    }
}

// -- key list --

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let keys: Vec<_> = objects
        .into_iter()
        .filter(|o| matches!(o.kind, ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey))
        .collect();

    let listing = KeyListing {
        keys: keys
            .iter()
            .map(|k| KeySummary {
                path: k.path.to_string(),
                kind: k.kind.to_string(),
                algorithm: k.algorithm.to_string(),
                created_at: k.created_at.to_rfc3339(),
            })
            .collect(),
    };

    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct KeyListing {
    keys: Vec<KeySummary>,
}

#[derive(Serialize)]
struct KeySummary {
    path: String,
    kind: String,
    algorithm: String,
    created_at: String,
}

impl TextRenderable for KeyListing {
    fn render_text(&self) -> String {
        if self.keys.is_empty() {
            return "No keys found.\n".to_string();
        }
        let mut out = String::new();
        let max_path = self.keys.iter().map(|k| k.path.len()).max().unwrap_or(10);
        out.push_str(&format!(
            "{:<width$}  {:<15}  {}\n",
            "PATH",
            "ALGORITHM",
            "CREATED",
            width = max_path
        ));
        for key in &self.keys {
            out.push_str(&format!(
                "{:<width$}  {:<15}  {}\n",
                key.path,
                key.algorithm,
                &key.created_at[..19],
                width = max_path
            ));
        }
        out
    }
}

// -- key show --

pub fn show(store: &Store, path_str: &str, format: OutputFormat) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str).map_err(|e| {
        let diag = Diagnostic::error(DiagCode::E0003, e.to_string());
        eprintln!("{}", diag.render_text());
        e
    })?;

    let obj = store.get_object(&path)?;
    match obj {
        Some(obj) => {
            let detail = KeyDetail {
                path: obj.path.to_string(),
                id: obj.id.to_string(),
                kind: obj.kind.to_string(),
                algorithm: obj.algorithm.to_string(),
                created_at: obj.created_at.to_rfc3339(),
                has_handle: obj.handle_blob.is_some(),
                metadata: obj.metadata.clone(),
            };
            println!("{}", render(&detail, format));
        }
        None => {
            let diag = Diagnostic::error(
                DiagCode::E0004,
                format!("object not found: {}", path),
            )
            .with_suggestion("run `tpm key list` to see available keys");
            eprintln!("{}", diag.render_text());
            anyhow::bail!("object not found: {}", path);
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct KeyDetail {
    path: String,
    id: String,
    kind: String,
    algorithm: String,
    created_at: String,
    has_handle: bool,
    metadata: serde_json::Value,
}

impl TextRenderable for KeyDetail {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("path:       {}\n", self.path));
        out.push_str(&format!("id:         {}\n", self.id));
        out.push_str(&format!("kind:       {}\n", self.kind));
        out.push_str(&format!("algorithm:  {}\n", self.algorithm));
        out.push_str(&format!("created:    {}\n", self.created_at));
        out.push_str(&format!(
            "handle:     {}\n",
            if self.has_handle { "present" } else { "none" }
        ));
        out
    }
}

// -- key sign --

pub fn sign(
    store: &Store,
    backend: &dyn TpmBackend,
    path_str: &str,
    input: &PathBuf,
    output: Option<&PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;

    let obj = store
        .get_object(&path)?
        .ok_or_else(|| anyhow::anyhow!("object not found: {}", path))?;

    let handle_blob = obj
        .handle_blob
        .ok_or_else(|| anyhow::anyhow!("key has no handle: {}", path))?;

    let handle = tpm_core::backend::KeyHandle {
        id: handle_blob,
        path: path.as_str().to_string(),
    };

    let data = std::fs::read(input)?;
    let signature = backend.sign(&handle, &data)?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &signature)?;
    }

    store.log_action(
        "key.sign",
        Some(path.as_str()),
        &serde_json::json!({"input": input.display().to_string()}),
    )?;

    let result = SignResult {
        key: path.to_string(),
        input: input.display().to_string(),
        signature_hex: hex_encode(&signature),
        output_file: output.map(|p| p.display().to_string()),
    };

    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct SignResult {
    key: String,
    input: String,
    signature_hex: String,
    output_file: Option<String>,
}

impl TextRenderable for SignResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("signed with: {}\n", self.key));
        out.push_str(&format!("input:       {}\n", self.input));
        out.push_str(&format!("signature:   {}\n", self.signature_hex));
        if let Some(f) = &self.output_file {
            out.push_str(&format!("written to:  {}\n", f));
        }
        out
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// -- key delete --

pub fn delete(store: &Store, path_str: &str, format: OutputFormat) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;

    let obj = store.get_object(&path)?;
    if obj.is_none() {
        let diag = Diagnostic::error(DiagCode::E0004, format!("object not found: {}", path))
            .with_suggestion("run `tpm key list` to see available keys");
        eprintln!("{}", diag.render_text());
        anyhow::bail!("object not found: {}", path);
    }

    store.delete_object(&path)?;
    store.log_action("key.delete", Some(path.as_str()), &serde_json::json!({}))?;

    let result = KeyDeleted {
        path: path.to_string(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct KeyDeleted {
    path: String,
}

impl TextRenderable for KeyDeleted {
    fn render_text(&self) -> String {
        format!("key deleted: {}\n", self.path)
    }
}

// -- key export-pub --

pub fn export_pub(
    store: &Store,
    path_str: &str,
    key_format: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;

    let obj = store
        .get_object(&path)?
        .ok_or_else(|| anyhow::anyhow!("object not found: {}", path))?;

    // Mock: generate a deterministic "public key" representation
    let pub_material = match key_format {
        "pem" => format!(
            "-----BEGIN PUBLIC KEY-----\n(mock {} public key for {})\n-----END PUBLIC KEY-----",
            obj.algorithm, obj.path
        ),
        "der" => format!("(mock DER for {})", obj.path),
        "raw" => hex_encode(obj.handle_blob.as_deref().unwrap_or(&[])),
        _ => anyhow::bail!("unsupported key format: {} (use pem, der, raw)", key_format),
    };

    let result = ExportPubResult {
        path: path.to_string(),
        algorithm: obj.algorithm.to_string(),
        key_format: key_format.to_string(),
        public_key: pub_material,
    };

    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct ExportPubResult {
    path: String,
    algorithm: String,
    key_format: String,
    public_key: String,
}

impl TextRenderable for ExportPubResult {
    fn render_text(&self) -> String {
        format!(
            "path:       {}\nalgorithm:  {}\nformat:     {}\n\n{}\n",
            self.path, self.algorithm, self.key_format, self.public_key
        )
    }
}
