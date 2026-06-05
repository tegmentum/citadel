//! Identity resource CLI commands.
//!
//! An identity composes a key + policy + intended usage + optional cert.

use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::TpmBackend;
use tpm_core::model::{Algorithm, Identity, IdentityUsage, ObjectKind, ObjectPath, TpmObject};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::service::{delete_identity_svc, init_identity, rotate_identity, InitIdentitySpec};
use tpm_core::store::Store;

use serde::Serialize;

#[allow(clippy::too_many_arguments)]
pub fn init(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    usage: &str,
    algorithm: &str,
    policy: Option<&str>,
    subject: Option<&str>,
    key_path: Option<&str>,
    pcr_bind: Option<&[u32]>,
    authority: bool,
    authorized_by: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    // Authority identity: an external-loadable approver key (the offline
    // PolicyAuthorize root). Signing keys bind to it with --authorized-by.
    if authority {
        if authorized_by.is_some() || pcr_bind.is_some() {
            anyhow::bail!("--authority cannot be combined with --authorized-by or --pcr-bind");
        }
        return init_authority(store, backend, name, usage, algorithm, subject, key_path, format);
    }

    // PolicyAuthorize-bound identity: the key signs under any measured
    // state the authority approves (upgradable policy, no re-key).
    if let Some(auth_name) = authorized_by {
        let indices = pcr_bind.ok_or_else(|| {
            anyhow::anyhow!("--authorized-by requires --pcr-bind to name the PCRs the approval covers")
        })?;
        return init_authorized(
            store, backend, name, usage, algorithm, subject, key_path, auth_name, indices, format,
        );
    }

    // PCR-bound identities create a TPM-policy-bound key so the TPM
    // enforces the measured state at sign time (see `init_pcr_bound`).
    if let Some(indices) = pcr_bind {
        return init_pcr_bound(store, backend, name, usage, algorithm, subject, key_path, indices, format);
    }

    let usage_parsed: IdentityUsage = usage.parse().map_err(|e: String| anyhow::anyhow!(e))?;

    let identity = init_identity(
        store,
        backend,
        InitIdentitySpec {
            name,
            usage: usage_parsed,
            algorithm,
            policy_name: policy,
            subject,
            key_path,
        },
    )?;

    let out = IdentityInitOutput {
        name: identity.name,
        id: identity.id.to_string(),
        usage: identity.usage.to_string(),
        key_object_id: identity.key_object_id.to_string(),
        subject: identity.subject,
    };
    println!("{}", render(&out, format));
    Ok(())
}

/// Create an identity whose signing key is bound (via TPM authPolicy) to
/// the current sha256 PCR state of `indices`. The TPM will only sign with
/// it while those PCRs match, so checkpoint signing is measured-state
/// enforced by hardware, not just the citadel-side gate.
#[allow(clippy::too_many_arguments)]
fn init_pcr_bound(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    usage: &str,
    algorithm: &str,
    subject: Option<&str>,
    key_path: Option<&str>,
    indices: &[u32],
    format: OutputFormat,
) -> anyhow::Result<()> {
    if store.get_identity(name)?.is_some() {
        anyhow::bail!("identity already exists: {}", name);
    }
    let usage_parsed: IdentityUsage = usage.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let alg: Algorithm = algorithm.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let key_path_str = key_path
        .map(String::from)
        .unwrap_or_else(|| format!("signing/{}", name));
    let path = ObjectPath::new(&key_path_str)?;
    if store.get_object(&path)?.is_some() {
        anyhow::bail!("object already exists: {}", path);
    }

    let bank = "sha256";
    // Bind the key to the CURRENT measured state.
    let auth_policy = backend.pcr_policy_digest(bank, indices)?;
    let handle = backend.create_key_with_policy(alg, &path, &auth_policy)?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm: alg,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({ "pcr_policy": { "bank": bank, "indices": indices } }),
    };
    store.insert_object(&obj)?;

    let identity = Identity {
        id: Uuid::new_v4(),
        name: name.to_string(),
        key_object_id: obj.id,
        policy_id: None,
        usage: usage_parsed,
        subject: subject.map(String::from),
        certificate_pem: None,
        created_at: Utc::now(),
        rotated_from: None,
    };
    store.insert_identity(&identity)?;
    store.log_action(
        "identity.init",
        Some(name),
        &serde_json::json!({ "usage": identity.usage.as_str(), "key": key_path_str, "pcr_bind": indices }),
    )?;

    let out = IdentityInitOutput {
        name: identity.name,
        id: identity.id.to_string(),
        usage: identity.usage.to_string(),
        key_object_id: identity.key_object_id.to_string(),
        subject: identity.subject,
    };
    println!("{}", render(&out, format));
    Ok(())
}

/// Create a PolicyAuthorize *authority* identity: an external-loadable
/// signing key that approves measured states for keys bound to it. Held
/// offline (HSM / air-gapped) in production — it is the upgrade root of
/// trust, so its compromise makes attacks indistinguishable from upgrades.
#[allow(clippy::too_many_arguments)]
fn init_authority(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    usage: &str,
    algorithm: &str,
    subject: Option<&str>,
    key_path: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if store.get_identity(name)?.is_some() {
        anyhow::bail!("identity already exists: {}", name);
    }
    let usage_parsed: IdentityUsage = usage.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let alg: Algorithm = algorithm.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let key_path_str = key_path
        .map(String::from)
        .unwrap_or_else(|| format!("authority/{}", name));
    let path = ObjectPath::new(&key_path_str)?;
    if store.get_object(&path)?.is_some() {
        anyhow::bail!("object already exists: {}", path);
    }

    let handle = backend.create_authority_key(alg, &path)?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm: alg,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({ "policy_authority": true }),
    };
    store.insert_object(&obj)?;

    let identity = Identity {
        id: Uuid::new_v4(),
        name: name.to_string(),
        key_object_id: obj.id,
        policy_id: None,
        usage: usage_parsed,
        subject: subject.map(String::from),
        certificate_pem: None,
        created_at: Utc::now(),
        rotated_from: None,
    };
    store.insert_identity(&identity)?;
    store.log_action(
        "identity.init",
        Some(name),
        &serde_json::json!({ "usage": identity.usage.as_str(), "key": key_path_str, "authority": true }),
    )?;

    let out = IdentityInitOutput {
        name: identity.name,
        id: identity.id.to_string(),
        usage: identity.usage.to_string(),
        key_object_id: identity.key_object_id.to_string(),
        subject: identity.subject,
    };
    println!("{}", render(&out, format));
    Ok(())
}

/// Create a signing identity bound to an `authority` via
/// TPM2_PolicyAuthorize: the key signs under any `indices` PolicyPCR
/// state the authority has approved (and that approval is witnessed in
/// the MMA log). Unlike `--pcr-bind`, an upgrade needs only a new
/// approval — the key itself never changes.
#[allow(clippy::too_many_arguments)]
fn init_authorized(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    usage: &str,
    algorithm: &str,
    subject: Option<&str>,
    key_path: Option<&str>,
    authority_name: &str,
    indices: &[u32],
    format: OutputFormat,
) -> anyhow::Result<()> {
    if store.get_identity(name)?.is_some() {
        anyhow::bail!("identity already exists: {}", name);
    }
    // Resolve the authority identity and its public (backend-agnostic).
    let authority = store
        .get_identity(authority_name)?
        .ok_or_else(|| anyhow::anyhow!("authority identity not found: {}", authority_name))?;
    let auth_key = store
        .get_object_by_id(&authority.key_object_id)?
        .ok_or_else(|| anyhow::anyhow!("authority '{}' references missing key", authority_name))?;
    let auth_handle_blob = auth_key
        .handle_blob
        .clone()
        .ok_or_else(|| anyhow::anyhow!("authority '{}' key has no handle blob", authority_name))?;
    let authority_pub = backend.public_blob(&tpm_core::backend::KeyHandle {
        id: auth_handle_blob,
        path: auth_key.path.to_string(),
    })?;

    let usage_parsed: IdentityUsage = usage.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let alg: Algorithm = algorithm.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let key_path_str = key_path
        .map(String::from)
        .unwrap_or_else(|| format!("signing/{}", name));
    let path = ObjectPath::new(&key_path_str)?;
    if store.get_object(&path)?.is_some() {
        anyhow::bail!("object already exists: {}", path);
    }

    let bank = "sha256";
    let handle = backend.create_key_authorized(alg, &path, &authority_pub)?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm: alg,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({
            "policy_authorize": { "authority": authority_name, "bank": bank, "indices": indices }
        }),
    };
    store.insert_object(&obj)?;

    let identity = Identity {
        id: Uuid::new_v4(),
        name: name.to_string(),
        key_object_id: obj.id,
        policy_id: None,
        usage: usage_parsed,
        subject: subject.map(String::from),
        certificate_pem: None,
        created_at: Utc::now(),
        rotated_from: None,
    };
    store.insert_identity(&identity)?;
    store.log_action(
        "identity.init",
        Some(name),
        &serde_json::json!({
            "usage": identity.usage.as_str(),
            "key": key_path_str,
            "authorized_by": authority_name,
            "pcr_bind": indices,
        }),
    )?;

    let out = IdentityInitOutput {
        name: identity.name,
        id: identity.id.to_string(),
        usage: identity.usage.to_string(),
        key_object_id: identity.key_object_id.to_string(),
        subject: identity.subject,
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn show(store: &Store, name: &str, format: OutputFormat) -> anyhow::Result<()> {
    let identity = store
        .get_identity(name)?
        .ok_or_else(|| anyhow::anyhow!("identity not found: {}", name))?;

    let key_path = store
        .list_objects()?
        .into_iter()
        .find(|o| o.id == identity.key_object_id)
        .map(|o| o.path.to_string());

    let policy_name = if let Some(pid) = identity.policy_id {
        store.get_policy_by_id(&pid)?.map(|p| p.name)
    } else {
        None
    };

    let out = IdentityDetail {
        name: identity.name,
        id: identity.id.to_string(),
        usage: identity.usage.to_string(),
        key_path,
        key_object_id: identity.key_object_id.to_string(),
        policy: policy_name,
        subject: identity.subject,
        certificate_present: identity.certificate_pem.is_some(),
        created_at: identity.created_at.to_rfc3339(),
        rotated_from: identity.rotated_from.map(|u| u.to_string()),
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let identities = store.list_identities()?;
    let out = IdentityListing {
        identities: identities
            .iter()
            .map(|i| IdentitySummary {
                name: i.name.clone(),
                usage: i.usage.to_string(),
                key_object_id: i.key_object_id.to_string(),
                subject: i.subject.clone(),
            })
            .collect(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn rotate(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let identity = rotate_identity(store, backend, name)?;
    let out = IdentityRotated {
        name: identity.name,
        new_key_object_id: identity.key_object_id.to_string(),
        rotated_from: identity
            .rotated_from
            .map(|u| u.to_string())
            .unwrap_or_default(),
    };
    println!("{}", render(&out, format));
    Ok(())
}

pub fn delete(store: &Store, name: &str, cascade: bool) -> anyhow::Result<()> {
    delete_identity_svc(store, name, cascade)?;
    if cascade {
        println!("identity deleted: {} (including backing key)", name);
    } else {
        println!("identity deleted: {} (key preserved)", name);
    }
    Ok(())
}

// -- Output types --

#[derive(Serialize)]
struct IdentityInitOutput {
    name: String,
    id: String,
    usage: String,
    key_object_id: String,
    subject: Option<String>,
}

impl TextRenderable for IdentityInitOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("identity created: {}\n", self.name));
        out.push_str(&format!("  id:      {}\n", self.id));
        out.push_str(&format!("  usage:   {}\n", self.usage));
        out.push_str(&format!("  key id:  {}\n", self.key_object_id));
        if let Some(ref s) = self.subject {
            out.push_str(&format!("  subject: {}\n", s));
        }
        out
    }
}

#[derive(Serialize)]
struct IdentityDetail {
    name: String,
    id: String,
    usage: String,
    key_path: Option<String>,
    key_object_id: String,
    policy: Option<String>,
    subject: Option<String>,
    certificate_present: bool,
    created_at: String,
    rotated_from: Option<String>,
}

impl TextRenderable for IdentityDetail {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("name:         {}\n", self.name));
        out.push_str(&format!("id:           {}\n", self.id));
        out.push_str(&format!("usage:        {}\n", self.usage));
        out.push_str(&format!(
            "key:          {}\n",
            self.key_path.as_deref().unwrap_or("(missing)")
        ));
        out.push_str(&format!("key id:       {}\n", self.key_object_id));
        out.push_str(&format!(
            "policy:       {}\n",
            self.policy.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!(
            "subject:      {}\n",
            self.subject.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!(
            "certificate:  {}\n",
            if self.certificate_present {
                "present"
            } else {
                "(none)"
            }
        ));
        out.push_str(&format!("created:      {}\n", self.created_at));
        if let Some(ref r) = self.rotated_from {
            out.push_str(&format!("rotated from: {}\n", r));
        }
        out
    }
}

#[derive(Serialize)]
struct IdentityListing {
    identities: Vec<IdentitySummary>,
}

#[derive(Serialize)]
struct IdentitySummary {
    name: String,
    usage: String,
    key_object_id: String,
    subject: Option<String>,
}

impl TextRenderable for IdentityListing {
    fn render_text(&self) -> String {
        if self.identities.is_empty() {
            return "No identities defined.\n".to_string();
        }
        let mut out = String::new();
        for i in &self.identities {
            out.push_str(&format!("  {} [{}]\n", i.name, i.usage));
            if let Some(ref s) = i.subject {
                out.push_str(&format!("    subject: {}\n", s));
            }
        }
        out
    }
}

#[derive(Serialize)]
struct IdentityRotated {
    name: String,
    new_key_object_id: String,
    rotated_from: String,
}

impl TextRenderable for IdentityRotated {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("identity rotated: {}\n", self.name));
        out.push_str(&format!("  new key id:    {}\n", self.new_key_object_id));
        out.push_str(&format!("  rotated from:  {}\n", self.rotated_from));
        out
    }
}
