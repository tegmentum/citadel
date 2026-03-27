use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;

use serde::Serialize;

/// List available recovery playbooks.
pub fn list(format: OutputFormat) -> anyhow::Result<()> {
    let listing = PlaybookListing {
        playbooks: PLAYBOOKS
            .iter()
            .map(|p| PlaybookSummary {
                name: p.name.to_string(),
                description: p.description.to_string(),
            })
            .collect(),
    };
    println!("{}", render(&listing, format));
    Ok(())
}

/// Show a specific recovery playbook.
pub fn show(name: &str, format: OutputFormat) -> anyhow::Result<()> {
    let playbook = PLAYBOOKS
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "playbook not found: '{}'\nrun `tpm recover list` to see available playbooks",
                name
            )
        })?;

    let detail = PlaybookDetail {
        name: playbook.name.to_string(),
        description: playbook.description.to_string(),
        when: playbook.when.to_string(),
        steps: playbook.steps.iter().map(|s| s.to_string()).collect(),
        warning: playbook.warning.map(|w| w.to_string()),
    };
    println!("{}", render(&detail, format));
    Ok(())
}

struct Playbook {
    name: &'static str,
    description: &'static str,
    when: &'static str,
    steps: &'static [&'static str],
    warning: Option<&'static str>,
}

const PLAYBOOKS: &[Playbook] = &[
    Playbook {
        name: "tpm-cleared",
        description: "Recover after TPM clear/reset",
        when: "The TPM was cleared (owner hierarchy reset), firmware was updated, or the TPM was replaced. Persistent handles and sealed data are lost.",
        steps: &[
            "run `tpm repair scan` to identify orphaned workspace objects",
            "run `tpm repair plan` to review proposed fixes",
            "run `tpm repair apply` to remove stale metadata",
            "run `tpm init` to re-establish workspace if needed",
            "recreate keys: `tpm key create <path>` for each needed key",
            "reseal secrets: `tpm secret seal <name> --input <file>` for each secret",
            "update PCR baselines: `tpm pcr baseline save <name> --index 0,7,11`",
        ],
        warning: Some("All previously sealed secrets are unrecoverable if the TPM was cleared. Ensure you have backup copies of critical secrets."),
    },
    Playbook {
        name: "handle-mismatch",
        description: "Fix persistent handle mismatches",
        when: "Workspace metadata references persistent handles that no longer exist on the TPM, typically after another tool modified TPM state.",
        steps: &[
            "run `tpm repair scan` to identify mismatched handles",
            "run `tpm object list` to see affected objects",
            "for each affected key: `tpm key delete <path>` then `tpm key create <path>`",
            "or run `tpm repair apply` for automatic cleanup",
        ],
        warning: None,
    },
    Playbook {
        name: "profile-drift",
        description: "Reconcile objects after profile change",
        when: "You switched profiles and some objects were created under old defaults (different algorithms, naming conventions, or policies).",
        steps: &[
            "run `tpm repair scan` to detect drifted objects",
            "run `tpm object list` to see all objects with their creation context",
            "decide whether to keep, rotate, or recreate each drifted object",
            "for rotation: `tpm key rotate <path>` creates new key with current profile defaults",
            "run `tpm gc plan` then `tpm gc apply` to clean up rotated predecessors",
        ],
        warning: None,
    },
    Playbook {
        name: "boot-change",
        description: "Update after expected boot configuration change",
        when: "You made intentional changes to boot configuration (kernel update, secure boot key rotation, BIOS update) and sealed secrets or PCR policies no longer match.",
        steps: &[
            "run `tpm pcr show --index 0,7,11` to see current PCR values",
            "run `tpm pcr baseline diff <baseline>` to see what changed",
            "if changes are expected, save new baseline: `tpm pcr baseline save <name> --index 0,7,11`",
            "reseal secrets that were bound to old PCR state: unseal with old state, then reseal",
            "update policies if needed: `tpm policy delete <old>` then `tpm policy create <new> --pcr ...`",
        ],
        warning: Some("If you cannot unseal secrets with the current boot state, you may need to boot back into the previous configuration first."),
    },
    Playbook {
        name: "metadata-corruption",
        description: "Recover from corrupted workspace database",
        when: "The SQLite workspace database is corrupted or inconsistent, commands fail with store errors.",
        steps: &[
            "export what you can: `tpm workspace export --output backup.json`",
            "check the database: run `sqlite3 <store_path> 'PRAGMA integrity_check'`",
            "if repairable: `tpm repair scan` then `tpm repair apply`",
            "if unrecoverable: delete the store file and run `tpm init`",
            "recreate objects from backup or from the TPM's persistent state",
            "run `tpm doctor` to verify workspace health",
        ],
        warning: Some("Back up the store file before attempting repair. The file location is shown by `tpm workspace info`."),
    },
    Playbook {
        name: "key-rotation",
        description: "Planned key rotation procedure",
        when: "You need to rotate a key as part of regular security practice or after a potential compromise.",
        steps: &[
            "check dependents: `tpm object dependents <path>`",
            "notify consumers of the upcoming rotation",
            "rotate: `tpm key rotate <path>`",
            "export new public key: `tpm key export-pub <path> --export-for <target>`",
            "distribute new public key to consumers",
            "verify new key works: `tpm key sign <path> --input test.bin`",
            "clean up: `tpm gc plan` then `tpm gc apply` to remove archived predecessor",
        ],
        warning: None,
    },
];

#[derive(Serialize)]
struct PlaybookListing {
    playbooks: Vec<PlaybookSummary>,
}

#[derive(Serialize)]
struct PlaybookSummary {
    name: String,
    description: String,
}

impl TextRenderable for PlaybookListing {
    fn render_text(&self) -> String {
        let mut out = String::new();
        let max_name = self
            .playbooks
            .iter()
            .map(|p| p.name.len())
            .max()
            .unwrap_or(10);
        out.push_str("Recovery playbooks:\n\n");
        for p in &self.playbooks {
            out.push_str(&format!(
                "  {:<nw$}  {}\n",
                p.name,
                p.description,
                nw = max_name
            ));
        }
        out.push_str("\nrun `tpm recover show <name>` for detailed steps\n");
        out
    }
}

#[derive(Serialize)]
struct PlaybookDetail {
    name: String,
    description: String,
    when: String,
    steps: Vec<String>,
    warning: Option<String>,
}

impl TextRenderable for PlaybookDetail {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("playbook: {}\n\n", self.name));
        out.push_str(&format!("  {}\n\n", self.description));
        out.push_str(&format!("when to use:\n  {}\n\n", self.when));
        out.push_str("steps:\n");
        for (i, step) in self.steps.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n", i + 1, step));
        }
        if let Some(ref warning) = self.warning {
            out.push_str(&format!("\nwarning: {}\n", warning));
        }
        out
    }
}
