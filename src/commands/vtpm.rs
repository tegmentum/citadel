//! `tpm vtpm` subcommand: provision a vTPM endorsement credential against a
//! hardware TPM, and inspect/verify it later.
//!
//! After provisioning the vTPM never needs to contact the hardware TPM again;
//! the credential is the durable proof of hardware endorsement.

use serde::Serialize;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::vtpm_credential::{default_credential_path, VtpmCredential};

#[cfg(feature = "tpm-hw")]
use chrono::Utc;
#[cfg(feature = "tpm-hw")]
use tpm_core::backend::HardwareBackend;
#[cfg(feature = "tpm-hw")]
use tpm_core::model::Algorithm;
#[cfg(feature = "tpm-hw")]
use tpm_core::vtpm_credential::VtpmIdentity;
#[cfg(feature = "tpm-hw")]
use uuid::Uuid;

/// Open the named hardware-style backend. Only `device` and `swtpm` make sense
/// here; we never provision against a vTPM (that would defeat the point).
#[cfg(feature = "tpm-hw")]
fn open_hw_backend(name: &str) -> anyhow::Result<HardwareBackend> {
    match name {
        "device" => HardwareBackend::new_device(),
        "swtpm" => {
            if let Ok(tcti) = std::env::var("TPM_SWTPM_TCTI") {
                HardwareBackend::new_from_tcti_str(&tcti)
            } else if let Ok(path) = std::env::var("TPM_SWTPM_SOCKET") {
                Ok(HardwareBackend::new_swtpm_unix(&path))
            } else {
                let host = std::env::var("TPM_SWTPM_HOST").unwrap_or_else(|_| "localhost".into());
                let port = std::env::var("TPM_SWTPM_PORT")
                    .ok()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(2321);
                HardwareBackend::new_swtpm_tcp(&host, port)
            }
        }
        other => anyhow::bail!(
            "unsupported hw backend '{}': use 'device' or 'swtpm'",
            other
        ),
    }
}

#[cfg(not(feature = "tpm-hw"))]
fn provision_unavailable() -> anyhow::Error {
    anyhow::anyhow!(
        "vtpm provisioning requires the hardware TPM backend; rebuild with --features tpm-hw"
    )
}

// -- provision --

#[cfg(feature = "tpm-hw")]
#[derive(Serialize)]
struct ProvisionedCredential {
    path: String,
    instance_id: String,
    created_at: String,
    vtpm_label: String,
    hw_backend: String,
}

#[cfg(feature = "tpm-hw")]
impl TextRenderable for ProvisionedCredential {
    fn render_text(&self) -> String {
        format!(
            "vTPM credential provisioned\n  path:        {}\n  instance:    {}\n  created:     {}\n  vtpm-label:  {}\n  hw-backend:  {}\n",
            self.path, self.instance_id, self.created_at, self.vtpm_label, self.hw_backend
        )
    }
}

#[cfg(feature = "tpm-hw")]
pub fn provision(
    hw_backend_name: &str,
    out_path: Option<&std::path::Path>,
    label: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    use tpm_core::backend::TpmBackend;

    let backend = open_hw_backend(hw_backend_name)?;

    let identity = VtpmIdentity {
        instance_id: Uuid::new_v4().to_string(),
        created_at: Utc::now().to_rfc3339(),
        vtpm_label: label.unwrap_or("vtpm-wasm").to_string(),
    };
    let signed_data = identity.to_signed_bytes()?;

    let ak_handle = backend.create_ak(Algorithm::EccP256)?;
    let key_data: serde_json::Value = serde_json::from_slice(&ak_handle.id)?;
    let ak_pub: Vec<u8> = serde_json::from_value(key_data["public"].clone())
        .map_err(|e| anyhow::anyhow!("extract AK public: {}", e))?;

    let signature = backend.sign(&ak_handle, &signed_data)?;

    let credential = VtpmCredential::new(
        identity.clone(),
        hw_backend_name.to_string(),
        ak_pub,
        signature,
    )?;

    let path = out_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_credential_path);
    credential.save(&path)?;

    let report = ProvisionedCredential {
        path: path.display().to_string(),
        instance_id: identity.instance_id,
        created_at: identity.created_at,
        vtpm_label: identity.vtpm_label,
        hw_backend: hw_backend_name.to_string(),
    };
    println!("{}", render(&report, format));
    Ok(())
}

#[cfg(not(feature = "tpm-hw"))]
pub fn provision(
    _hw_backend_name: &str,
    _out_path: Option<&std::path::Path>,
    _label: Option<&str>,
    _format: OutputFormat,
) -> anyhow::Result<()> {
    Err(provision_unavailable())
}

// -- show --

#[derive(Serialize)]
struct CredentialView {
    path: String,
    version: u8,
    instance_id: String,
    created_at: String,
    vtpm_label: String,
    hw_backend: String,
    hw_ak_pub_len: usize,
    signature_len: usize,
}

impl TextRenderable for CredentialView {
    fn render_text(&self) -> String {
        format!(
            "vTPM credential\n  path:         {}\n  version:      {}\n  instance:     {}\n  created:      {}\n  vtpm-label:   {}\n  hw-backend:   {}\n  ak-pub-bytes: {}\n  sig-bytes:    {}\n",
            self.path,
            self.version,
            self.instance_id,
            self.created_at,
            self.vtpm_label,
            self.hw_backend,
            self.hw_ak_pub_len,
            self.signature_len,
        )
    }
}

pub fn show(path: Option<&std::path::Path>, format: OutputFormat) -> anyhow::Result<()> {
    let path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_credential_path);
    let cred = VtpmCredential::load(&path)?;
    let view = CredentialView {
        path: path.display().to_string(),
        version: cred.version,
        instance_id: cred.identity.instance_id,
        created_at: cred.identity.created_at,
        vtpm_label: cred.identity.vtpm_label,
        hw_backend: cred.hw_backend_label,
        hw_ak_pub_len: cred.hw_ak_pub.len(),
        signature_len: cred.signature.len(),
    };
    println!("{}", render(&view, format));
    Ok(())
}

// -- verify --

#[cfg(feature = "tpm-hw")]
#[derive(Serialize)]
struct VerifyResult {
    path: String,
    instance_id: String,
    hw_backend: String,
    signature_valid: bool,
}

#[cfg(feature = "tpm-hw")]
impl TextRenderable for VerifyResult {
    fn render_text(&self) -> String {
        format!(
            "vTPM credential verification\n  path:        {}\n  instance:    {}\n  hw-backend:  {}\n  signature:   {}\n",
            self.path,
            self.instance_id,
            self.hw_backend,
            if self.signature_valid { "valid" } else { "INVALID" },
        )
    }
}

#[cfg(feature = "tpm-hw")]
pub fn verify(
    hw_backend_name: &str,
    path: Option<&std::path::Path>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_credential_path);
    let cred = VtpmCredential::load(&path)?;

    let backend = open_hw_backend(hw_backend_name)?;
    let valid = backend.verify_signature(&cred.hw_ak_pub, &cred.signed_data, &cred.signature)?;

    let result = VerifyResult {
        path: path.display().to_string(),
        instance_id: cred.identity.instance_id,
        hw_backend: hw_backend_name.to_string(),
        signature_valid: valid,
    };
    println!("{}", render(&result, format));
    if !valid {
        anyhow::bail!("credential signature did not verify");
    }
    Ok(())
}

#[cfg(not(feature = "tpm-hw"))]
pub fn verify(
    _hw_backend_name: &str,
    _path: Option<&std::path::Path>,
    _format: OutputFormat,
) -> anyhow::Result<()> {
    Err(provision_unavailable())
}
