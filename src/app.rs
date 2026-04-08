use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tpm_core::output::OutputFormat;

#[derive(Parser)]
#[command(name = "tpm", about = "TPM operator platform", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Output format
    #[arg(long, global = true, default_value = "text", value_parser = parse_output_format)]
    pub format: OutputFormat,

    /// Enable verbose output
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Path to the metadata store
    #[arg(long, global = true, env = "TPM_STORE_PATH")]
    pub store_path: Option<PathBuf>,

    /// TPM backend to use (auto, mock, device, swtpm, vtpm)
    #[arg(long, global = true, default_value = "auto", env = "TPM_BACKEND")]
    pub backend: String,

    /// Dry-run: show what would happen without executing
    #[arg(long, global = true)]
    pub plan: bool,

    /// Shorthand for --format json
    #[arg(long, global = true)]
    pub json: bool,
}

fn parse_output_format(s: &str) -> Result<OutputFormat, String> {
    s.parse()
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize workspace with default profile
    Init {
        /// Profile name to create
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show TPM and workspace status
    Status,
    /// Run diagnostic health checks
    Doctor,
    /// Show TPM capabilities
    Capabilities,
    /// Collect debug diagnostic bundle
    Debug {
        /// Output file for the bundle
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Key management
    #[command(subcommand)]
    Key(KeyCommand),
    /// Remote attestation
    #[command(subcommand)]
    Attest(AttestCommand),
    /// Secret sealing and unsealing
    #[command(subcommand)]
    Secret(SecretCommand),
    /// NV (non-volatile) storage management
    #[command(subcommand)]
    Nv(NvCommand),
    /// PCR (Platform Configuration Register) operations
    #[command(subcommand)]
    Pcr(PcrCommand),
    /// Policy management
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Object inspection
    #[command(subcommand)]
    Object(ObjectCommand),
    /// Profile management
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Repair workspace issues
    #[command(subcommand)]
    Repair(RepairCommand),
    /// Garbage collect stale objects
    #[command(subcommand)]
    Gc(GcCommand),
    /// Recovery playbooks for common situations
    #[command(subcommand)]
    Recover(RecoverCommand),
    /// Manage swtpm simulator
    #[command(subcommand)]
    Simulator(SimulatorCommand),
    /// View audit log
    #[command(subcommand)]
    Log(LogCommand),
    /// Browse built-in templates
    #[command(subcommand)]
    Template(TemplateCommand),
    /// Workspace management
    #[command(subcommand)]
    Workspace(WorkspaceCommand),
    /// Explain a TPM concept
    Explain {
        /// Concept to explain (pcr, policy, hierarchy, key, seal, attestation, nv, ek, ak, handle, session, dictionary-attack)
        concept: String,
    },
    /// Daemon management
    #[command(subcommand)]
    Daemon(DaemonCommand),
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        shell: String,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Create a new key
    Create {
        /// Object path (e.g. signing/release)
        path: String,

        /// Algorithm
        #[arg(long, short, default_value = "ecc-p256")]
        algorithm: String,

        /// Attach a named policy
        #[arg(long)]
        policy: Option<String>,
    },
    /// List all keys
    List,
    /// Show key details
    Show {
        /// Object path
        path: String,
    },
    /// Sign data with a key
    Sign {
        /// Key object path
        path: String,

        /// Input file to sign
        #[arg(long)]
        input: PathBuf,

        /// Output file for signature
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Delete a key
    Delete {
        /// Object path
        path: String,
    },
    /// Export public key material
    ExportPub {
        /// Object path
        path: String,

        /// Export format (pem, der, raw)
        #[arg(long, default_value = "pem")]
        key_format: String,

        /// Integration target (openssl, ssh, cosign, pkcs11)
        #[arg(long = "export-for")]
        target: Option<String>,
    },
    /// Rotate a key (create new, archive old)
    Rotate {
        /// Object path
        path: String,
    },
}

#[derive(Subcommand)]
pub enum AttestCommand {
    /// Create an attestation key
    AkCreate {
        /// AK name (e.g. attest/main)
        name: String,

        /// Algorithm
        #[arg(long, short, default_value = "ecc-p256")]
        algorithm: String,
    },
    /// Generate a TPM quote (signed PCR attestation)
    Quote {
        /// Attestation key name
        #[arg(long)]
        ak: String,

        /// PCR bank
        #[arg(long, default_value = "sha256")]
        bank: String,

        /// PCR indices (comma-separated)
        #[arg(long, value_delimiter = ',', default_values_t = vec![0, 7, 11])]
        pcr: Vec<u32>,

        /// Nonce (challenge from verifier)
        #[arg(long)]
        nonce: Option<String>,

        /// Output file for quote JSON
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Verify a TPM quote
    Verify {
        /// Path to quote JSON file
        #[arg(long)]
        quote: std::path::PathBuf,

        /// Expected nonce
        #[arg(long)]
        nonce: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Create a new policy
    Create {
        /// Policy name
        name: String,

        /// PCR indices (comma-separated, e.g. 7,11)
        #[arg(long, value_delimiter = ',')]
        pcr: Vec<u32>,

        /// PCR bank
        #[arg(long, default_value = "sha256")]
        pcr_bank: String,

        /// Require password/auth value
        #[arg(long)]
        password: bool,
    },
    /// List all policies
    List,
    /// Show policy details
    Show {
        /// Policy name
        name: String,
    },
    /// Explain what a policy requires
    Explain {
        /// Policy name
        name: String,
    },
    /// Delete a policy
    Delete {
        /// Policy name
        name: String,
    },
    /// Compile a policy from a YAML file
    Compile {
        /// Path to policy YAML file
        file: std::path::PathBuf,
    },
    /// Test whether a policy can be satisfied on this system
    Test {
        /// Policy name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum SecretCommand {
    /// Seal a secret
    Seal {
        /// Secret name (e.g. db/password)
        name: String,

        /// Input file containing the secret
        #[arg(long)]
        input: std::path::PathBuf,

        /// Attach a named policy
        #[arg(long)]
        policy: Option<String>,
    },
    /// Unseal a secret
    Unseal {
        /// Secret name
        name: String,

        /// Output file (if omitted, prints to stdout)
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// List sealed secrets
    List,
}

#[derive(Subcommand)]
pub enum NvCommand {
    /// Define an NV index
    Define {
        /// NV index name (e.g. config/build-id)
        name: String,

        /// Size in bytes
        #[arg(long)]
        size: usize,
    },
    /// Write data to an NV index
    Write {
        /// NV index name
        name: String,

        /// Input file
        #[arg(long)]
        input: std::path::PathBuf,
    },
    /// Read data from an NV index
    Read {
        /// NV index name
        name: String,

        /// Output file (if omitted, prints to stdout)
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// List NV indices
    List,
    /// Delete an NV index
    Delete {
        /// NV index name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum PcrCommand {
    /// Show current PCR values
    Show {
        /// PCR bank
        #[arg(long, default_value = "sha256")]
        bank: String,

        /// PCR indices (comma-separated)
        #[arg(long, value_delimiter = ',', default_values_t = vec![0, 1, 2, 3, 4, 5, 6, 7])]
        index: Vec<u32>,
    },
    /// PCR baseline management
    #[command(subcommand)]
    Baseline(PcrBaselineCommand),
}

#[derive(Subcommand)]
pub enum PcrBaselineCommand {
    /// Save current PCR state as a named baseline
    Save {
        /// Baseline name
        name: String,

        /// PCR bank
        #[arg(long, default_value = "sha256")]
        bank: String,

        /// PCR indices (comma-separated)
        #[arg(long, value_delimiter = ',', default_values_t = vec![0, 1, 2, 3, 4, 5, 6, 7])]
        index: Vec<u32>,
    },
    /// Compare current PCR state against a saved baseline
    Diff {
        /// Baseline name
        name: String,
    },
    /// List saved baselines
    List,
}

#[derive(Subcommand)]
pub enum ObjectCommand {
    /// List all workspace objects
    List,
    /// Show workspace object tree
    Tree,
    /// Show what depends on an object
    Dependents {
        /// Object path
        path: String,
    },
    /// Rename an object
    Rename {
        /// Current path
        from: String,
        /// New path
        to: String,
    },
    /// Retire an object (mark inactive but keep metadata)
    Retire {
        /// Object path
        path: String,
    },
    /// Reactivate a retired object
    Activate {
        /// Object path
        path: String,
    },
}

#[derive(Subcommand)]
pub enum GcCommand {
    /// Show what would be garbage collected
    Plan,
    /// Remove stale objects
    Apply,
}

#[derive(Subcommand)]
pub enum RecoverCommand {
    /// List available recovery playbooks
    List,
    /// Show a recovery playbook
    Show {
        /// Playbook name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// List all profiles
    List,
    /// Show profile details
    Show {
        /// Profile name (default: active profile)
        name: Option<String>,
    },
    /// Set the active profile
    Set {
        /// Profile name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum RepairCommand {
    /// Scan for workspace issues
    Scan,
    /// Show repair plan without applying
    Plan,
    /// Apply automatic repairs
    Apply,
}

#[derive(Subcommand)]
pub enum SimulatorCommand {
    /// Start the swtpm simulator
    Start {
        /// State directory for swtpm
        #[arg(long)]
        state_dir: Option<String>,
    },
    /// Stop the swtpm simulator
    Stop {
        /// State directory for swtpm
        #[arg(long)]
        state_dir: Option<String>,
    },
    /// Show simulator status
    Status {
        /// State directory for swtpm
        #[arg(long)]
        state_dir: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum LogCommand {
    /// Show recent audit log entries
    Show {
        /// Filter by object path
        #[arg(long)]
        object: Option<String>,

        /// Filter by action (substring match)
        #[arg(long)]
        action: Option<String>,

        /// Number of entries to show
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub enum TemplateCommand {
    /// List available templates
    List,
    /// Show template details
    Show {
        /// Template name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum WorkspaceCommand {
    /// Show workspace summary
    Info,
    /// Export workspace metadata to JSON
    Export {
        /// Output file path
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Import workspace metadata from JSON
    Import {
        /// Input file path
        #[arg(long)]
        input: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
pub enum DaemonCommand {
    /// Run the daemon
    Run {
        /// Listen address
        #[arg(long, default_value = "127.0.0.1:7701")]
        listen: String,
    },
    /// Show daemon status
    Status,
}
