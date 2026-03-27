use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;

use serde::Serialize;

/// Built-in templates for common TPM configurations.
const TEMPLATES: &[Template] = &[
    Template {
        name: "signing-key",
        description: "General-purpose signing key (ECC P-256)",
        kind: "key",
        algorithm: "ecc-p256",
        example: "tpm key create signing/my-key --algorithm ecc-p256",
    },
    Template {
        name: "signing-key-rsa",
        description: "RSA signing key (RSA 2048)",
        kind: "key",
        algorithm: "rsa2048",
        example: "tpm key create signing/my-key --algorithm rsa2048",
    },
    Template {
        name: "attestation-key",
        description: "Attestation key for remote quote generation",
        kind: "ak",
        algorithm: "ecc-p256",
        example: "tpm attest ak-create attest/main",
    },
    Template {
        name: "boot-policy",
        description: "PCR policy for boot integrity (PCR 0, 7)",
        kind: "policy",
        algorithm: "",
        example: "tpm policy create boot-policy --pcr 0,7",
    },
    Template {
        name: "boot-secret",
        description: "Secret sealed to boot state (PCR 7, 11)",
        kind: "secret",
        algorithm: "",
        example: "tpm policy create boot-seal --pcr 7,11 && tpm secret seal my-secret --input secret.txt --policy boot-seal",
    },
    Template {
        name: "ci-signer",
        description: "CI/CD artifact signing setup",
        kind: "profile",
        algorithm: "ecc-p256",
        example: "tpm init --profile ci-signer && tpm key create signing/release",
    },
    Template {
        name: "node-identity",
        description: "Machine identity with AK for attestation",
        kind: "profile",
        algorithm: "ecc-p256",
        example: "tpm init && tpm attest ak-create attest/node && tpm attest quote --ak attest/node --pcr 0,7,11",
    },
    Template {
        name: "disk-unlock",
        description: "PCR-bound secret for disk encryption key",
        kind: "secret",
        algorithm: "",
        example: "tpm policy create luks --pcr 7 && tpm secret seal luks/key --input keyfile --policy luks",
    },
];

struct Template {
    name: &'static str,
    description: &'static str,
    kind: &'static str,
    algorithm: &'static str,
    example: &'static str,
}

pub fn list(format: OutputFormat) -> anyhow::Result<()> {
    let listing = TemplateListing {
        templates: TEMPLATES
            .iter()
            .map(|t| TemplateSummary {
                name: t.name.to_string(),
                kind: t.kind.to_string(),
                description: t.description.to_string(),
            })
            .collect(),
    };
    println!("{}", render(&listing, format));
    Ok(())
}

pub fn show(name: &str, format: OutputFormat) -> anyhow::Result<()> {
    let tmpl = TEMPLATES
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("template not found: {}\nrun `tpm template list` to see available templates", name))?;

    let detail = TemplateDetail {
        name: tmpl.name.to_string(),
        kind: tmpl.kind.to_string(),
        algorithm: if tmpl.algorithm.is_empty() {
            None
        } else {
            Some(tmpl.algorithm.to_string())
        },
        description: tmpl.description.to_string(),
        example: tmpl.example.to_string(),
    };
    println!("{}", render(&detail, format));
    Ok(())
}

#[derive(Serialize)]
struct TemplateListing {
    templates: Vec<TemplateSummary>,
}

#[derive(Serialize)]
struct TemplateSummary {
    name: String,
    kind: String,
    description: String,
}

impl TextRenderable for TemplateListing {
    fn render_text(&self) -> String {
        let mut out = String::new();
        let max_name = self
            .templates
            .iter()
            .map(|t| t.name.len())
            .max()
            .unwrap_or(10);
        let max_kind = self
            .templates
            .iter()
            .map(|t| t.kind.len())
            .max()
            .unwrap_or(6);

        out.push_str(&format!(
            "{:<nw$}  {:<kw$}  {}\n",
            "NAME",
            "KIND",
            "DESCRIPTION",
            nw = max_name,
            kw = max_kind
        ));
        for t in &self.templates {
            out.push_str(&format!(
                "{:<nw$}  {:<kw$}  {}\n",
                t.name,
                t.kind,
                t.description,
                nw = max_name,
                kw = max_kind
            ));
        }
        out
    }
}

#[derive(Serialize)]
struct TemplateDetail {
    name: String,
    kind: String,
    algorithm: Option<String>,
    description: String,
    example: String,
}

impl TextRenderable for TemplateDetail {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("template: {}\n", self.name));
        out.push_str(&format!("  kind:        {}\n", self.kind));
        if let Some(ref alg) = self.algorithm {
            out.push_str(&format!("  algorithm:   {}\n", alg));
        }
        out.push_str(&format!("  description: {}\n", self.description));
        out.push_str(&format!("\n  example:\n    $ {}\n", self.example));
        out
    }
}
