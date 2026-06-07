use std::path::PathBuf;

use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::TpmBackend;
use tpm_core::diag::TpmError;
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
    policy_name: Option<&str>,
    format: OutputFormat,
    plan_mode: bool,
) -> anyhow::Result<()> {
    if plan_mode {
        // Validate the inputs enough to show a meaningful plan without
        // performing any store writes.
        let _ = ObjectPath::new(path_str).inspect_err(|e| {
            let err = TpmError::invalid_path(path_str, &e.to_string());
            err.emit();
        })?;
        let _algorithm: Algorithm = algorithm_str
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        crate::plan::show_plan(&[crate::plan::PlannedAction {
            action: "create signing key".to_string(),
            target: Some(path_str.to_string()),
            details: vec![
                ("algorithm".to_string(), algorithm_str.to_string()),
                (
                    "policy".to_string(),
                    policy_name.unwrap_or("(none)").to_string(),
                ),
            ],
            risk: crate::plan::Risk::Low,
            reversible: true,
        }]);
        return Ok(());
    }

    let obj = tpm_core::service::create_key(
        store,
        backend,
        tpm_core::service::CreateKeySpec {
            path: path_str,
            algorithm: algorithm_str,
            policy_name,
        },
    )
    .inspect_err(|e| {
        // Best-effort: if it's a TpmError, emit the structured diagnostic.
        if let Some(tpm_err) = e.downcast_ref::<TpmError>() {
            tpm_err.emit();
        }
    })?;

    let summary = KeyCreated {
        path: obj.path.to_string(),
        algorithm: obj.algorithm.to_string(),
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
        .filter(|o| {
            matches!(
                o.kind,
                ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
            )
        })
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
    let path = ObjectPath::new(path_str).inspect_err(|e| {
        let err = TpmError::invalid_path(path_str, &e.to_string());
        err.emit();
    })?;

    let obj = store.get_object(&path)?.ok_or_else(|| {
        let err = TpmError::object_not_found(path_str);
        err.emit();
        err
    })?;

    let policy_name = if let Some(pid) = obj.policy_id {
        store.get_policy_by_id(&pid)?.map(|p| p.name)
    } else {
        None
    };

    let detail = KeyDetail {
        path: obj.path.to_string(),
        id: obj.id.to_string(),
        kind: obj.kind.to_string(),
        algorithm: obj.algorithm.to_string(),
        policy: policy_name,
        created_at: obj.created_at.to_rfc3339(),
        has_handle: obj.handle_blob.is_some(),
        metadata: obj.metadata.clone(),
    };
    println!("{}", render(&detail, format));
    Ok(())
}

#[derive(Serialize)]
struct KeyDetail {
    path: String,
    id: String,
    kind: String,
    algorithm: String,
    policy: Option<String>,
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
        out.push_str(&format!(
            "policy:     {}\n",
            self.policy.as_deref().unwrap_or("(none)")
        ));
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

    if store.get_object(&path)?.is_none() {
        let err = TpmError::object_not_found(path_str);
        err.emit();
        return Err(err.into());
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
    target: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;

    let obj = store
        .get_object(&path)?
        .ok_or_else(|| anyhow::anyhow!("object not found: {}", path))?;

    let handle_hex = hex_encode(obj.handle_blob.as_deref().unwrap_or(&[]));

    // Determine format based on target integration
    let (actual_format, pub_material, integration_hint) = match target {
        Some("openssl") => (
            "pem",
            format!(
                "-----BEGIN PUBLIC KEY-----\n(mock {} public key for {})\n-----END PUBLIC KEY-----",
                obj.algorithm, obj.path
            ),
            Some("use with: openssl dgst -verify key.pem -signature sig.bin data.bin".to_string()),
        ),
        Some("ssh") => (
            "ssh",
            format!(
                "ssh-{} {} tpm:{}",
                match obj.algorithm {
                    Algorithm::EccP256 => "ed25519",
                    Algorithm::EccP384 => "ed25519",
                    Algorithm::Rsa2048 => "rsa",
                    Algorithm::Rsa3072 => "rsa",
                },
                handle_hex,
                obj.path
            ),
            Some("add to ~/.ssh/authorized_keys or use as SSH host key".to_string()),
        ),
        Some("cosign") => (
            "pem",
            format!(
                "-----BEGIN PUBLIC KEY-----\n(mock {} public key for {})\n-----END PUBLIC KEY-----",
                obj.algorithm, obj.path
            ),
            Some("use with: cosign verify --key key.pem <image>".to_string()),
        ),
        Some("pkcs11") => (
            "uri",
            format!("pkcs11:model=TPM;manufacturer=mock;object={}", obj.path),
            Some("use as PKCS#11 URI reference to TPM-backed key".to_string()),
        ),
        Some(other) => {
            anyhow::bail!(
                "unknown integration target: '{}'\navailable: openssl, ssh, cosign, pkcs11",
                other
            )
        }
        None => {
            let material = match key_format {
                "pem" => format!(
                    "-----BEGIN PUBLIC KEY-----\n(mock {} public key for {})\n-----END PUBLIC KEY-----",
                    obj.algorithm, obj.path
                ),
                "der" => format!("(mock DER for {})", obj.path),
                "raw" => handle_hex,
                _ => anyhow::bail!("unsupported key format: {} (use pem, der, raw)", key_format),
            };
            (key_format, material, None)
        }
    };

    let result = ExportPubResult {
        path: path.to_string(),
        algorithm: obj.algorithm.to_string(),
        key_format: actual_format.to_string(),
        public_key: pub_material,
        integration_hint,
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
    integration_hint: Option<String>,
}

impl TextRenderable for ExportPubResult {
    fn render_text(&self) -> String {
        let mut out = format!(
            "path:       {}\nalgorithm:  {}\nformat:     {}\n\n{}\n",
            self.path, self.algorithm, self.key_format, self.public_key
        );
        if let Some(ref hint) = self.integration_hint {
            out.push_str(&format!("\nhint: {}\n", hint));
        }
        out
    }
}

// -- key rotate --

pub fn rotate(
    store: &Store,
    backend: &dyn TpmBackend,
    path_str: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;

    let old_obj = store.get_object(&path)?.ok_or_else(|| {
        let err = TpmError::object_not_found(path_str);
        err.emit();
        err
    })?;

    // Archive the old key by renaming it
    let old_name = format!("{}-rotated-{}", path_str, Utc::now().format("%Y%m%d%H%M%S"));
    let old_path = ObjectPath::new(&old_name)?;

    // Delete old from store and re-insert with archived name
    store.delete_object(&path)?;
    let archived = TpmObject {
        path: old_path.clone(),
        metadata: serde_json::json!({
            "rotated_from": path_str,
            "rotated_at": Utc::now().to_rfc3339(),
            "original_metadata": old_obj.metadata,
        }),
        ..old_obj.clone()
    };
    store.insert_object(&archived)?;

    // Create new key with same algorithm
    let handle = backend.create_key(old_obj.algorithm, &path)?;
    let new_obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: old_obj.kind,
        algorithm: old_obj.algorithm,
        policy_id: old_obj.policy_id,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({
            "predecessor": old_name,
        }),
    };
    store.insert_object(&new_obj)?;

    store.log_action(
        "key.rotate",
        Some(path.as_str()),
        &serde_json::json!({
            "old_id": old_obj.id.to_string(),
            "new_id": new_obj.id.to_string(),
            "archived_as": old_name,
        }),
    )?;

    let result = RotateResult {
        path: path.to_string(),
        new_id: new_obj.id.to_string(),
        algorithm: new_obj.algorithm.to_string(),
        archived_as: old_name,
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct RotateResult {
    path: String,
    new_id: String,
    algorithm: String,
    archived_as: String,
}

impl TextRenderable for RotateResult {
    fn render_text(&self) -> String {
        format!(
            "key rotated: {}\n  new id:    {}\n  algorithm: {}\n  archived:  {}\n",
            self.path, self.new_id, self.algorithm, self.archived_as
        )
    }
}
