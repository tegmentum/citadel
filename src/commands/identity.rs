//! Identity resource CLI commands.
//!
//! An identity composes a key + policy + intended usage + optional cert.

use tpm_core::backend::TpmBackend;
use tpm_core::model::IdentityUsage;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::service::{delete_identity_svc, init_identity, rotate_identity, InitIdentitySpec};
use tpm_core::store::Store;

use serde::Serialize;

pub fn init(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
    usage: &str,
    algorithm: &str,
    policy: Option<&str>,
    subject: Option<&str>,
    key_path: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
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
