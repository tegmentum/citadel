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
    /// Apply a workspace manifest (declarative)
    Apply {
        /// Path to manifest YAML file
        #[arg(long)]
        file: std::path::PathBuf,
        /// Force destructive changes (e.g. key rotation on algorithm drift)
        #[arg(long)]
        force: bool,
    },
    /// Show drift between manifest and current workspace state
    Diff {
        /// Path to manifest YAML file
        #[arg(long)]
        file: std::path::PathBuf,
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
        /// Concept to explain
        #[arg(value_parser = ["pcr", "policy", "hierarchy", "key", "seal", "attestation", "nv", "ek", "ak", "handle", "session", "dictionary-attack"])]
        concept: String,
    },
    /// Identity management (composite: key + policy + usage + cert)
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Tamper-evident secure log (hash-chained, Merkle-sealed, TPM-signed)
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Measure artifacts/applications into the Merkle-anchored log
    #[command(subcommand)]
    Measure(MeasureCommand),
    /// Render the workspace dependency graph
    Graph,
    /// Daemon management
    #[command(subcommand)]
    Daemon(DaemonCommand),
    /// vTPM endorsement (provision a hardware-rooted credential the vTPM can carry offline)
    #[command(subcommand)]
    Vtpm(VtpmCommand),
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
    /// Show fragility rating (how likely this policy is to break)
    Fragility {
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
    /// Extend a PCR with a measurement: PCR = H(PCR || digest)
    Extend {
        /// PCR bank
        #[arg(long, default_value = "sha256")]
        bank: String,

        /// PCR index to extend
        index: u32,

        /// Hash a file's contents and extend with the resulting digest
        #[arg(long, conflicts_with = "value")]
        input: Option<std::path::PathBuf>,

        /// Extend with this raw digest (hex), must match the bank size
        #[arg(long, conflicts_with = "input")]
        value: Option<String>,
    },
    /// PCR baseline management
    #[command(subcommand)]
    Baseline(PcrBaselineCommand),
}

#[derive(Subcommand)]
pub enum MeasureCommand {
    /// Measure an artifact directly (citadel hashes it)
    File {
        /// Path to the artifact to measure
        artifact: std::path::PathBuf,

        /// Logical kind of the artifact
        #[arg(long, default_value = "binary")]
        kind: String,

        /// Hash bank
        #[arg(long, default_value = "sha256")]
        bank: String,

        /// Also extend this PCR index with the measurement digest
        #[arg(long)]
        pcr: Option<u32>,
    },
    /// Ingest the kernel IMA runtime measurement list (delegated source)
    Ima {
        /// Read IMA measurements from this file instead of the default
        /// /sys/kernel/security/ima/ascii_runtime_measurements
        #[arg(long)]
        from: Option<std::path::PathBuf>,
    },
    /// Seal a Merkle segment over pending measurements (the tree root)
    Checkpoint,
    /// Sign a sealed segment's root with a TPM-backed identity
    Sign {
        /// Segment id to sign
        segment_id: u64,

        /// Identity name (see `tpm identity list`)
        #[arg(long)]
        identity: String,
    },
    /// Prove a measurement (by seqno) is included under a sealed root
    Verify {
        /// Measurement entry seqno
        seqno: u64,
    },
    /// List sealed measurement segments (Merkle roots)
    List,
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
pub enum AuditCommand {
    /// Append a new entry to the secure log.
    Append {
        /// Event type (e.g. "user.login", "key.sign").
        #[arg(long)]
        event: String,
        /// Severity label.
        #[arg(long, default_value = "info")]
        severity: String,
        /// Producer identifier (e.g. component name).
        #[arg(long, default_value = "cli")]
        producer: String,
        /// Payload bytes read from a file (use `-` for stdin).
        #[arg(long)]
        payload_file: Option<std::path::PathBuf>,
        /// Payload as an inline UTF-8 string.
        #[arg(long)]
        payload: Option<String>,
        /// Target stream.
        #[arg(long, default_value = "default")]
        stream: String,
        /// Encrypt the payload under the master KEK (see `audit key`).
        #[arg(long)]
        encrypt: bool,
    },
    /// Read a single entry by seqno.
    Show {
        seqno: u64,
        /// Decrypt the payload if it was stored encrypted.
        #[arg(long)]
        decrypt: bool,
    },
    /// Master KEK management for envelope encryption (Phase 5).
    #[command(subcommand)]
    Key(AuditKeyCommand),
    /// Secure log stream management (multi-stream).
    #[command(subcommand)]
    Streams(AuditStreamsCommand),
    /// Show the current head (highest seqno) for a stream.
    Head {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Chain operations.
    #[command(subcommand)]
    Chain(AuditChainCommand),
    /// Segment operations (Merkle-sealed windows).
    #[command(subcommand)]
    Segments(AuditSegmentsCommand),
    /// Build a Merkle inclusion proof for a single entry.
    Prove {
        /// Entry sequence number.
        seqno: u64,
    },
    /// Sign a closed segment's checkpoint with a TPM-backed identity.
    Sign {
        /// Segment id to sign.
        segment_id: u64,
        /// Identity name (see `tpm identity list`).
        #[arg(long)]
        identity: String,
    },
    /// Verify the full checkpoint chain from genesis to head.
    Verify {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Emit the witness submission JSON for a stream's current head.
    /// POST it to a witness service (e.g. `tpmd /v1/audit/witness`).
    Publish {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Check the anti-rollback head file against the live database.
    Rollback {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Witness receipt management.
    #[command(subcommand)]
    Witness(AuditWitnessCommand),
}

#[derive(Subcommand)]
pub enum AuditWitnessCommand {
    /// List all witness receipts for a stream.
    List {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Show the latest witness receipt for a stream.
    Latest {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Record a witness receipt from a locally-held submission JSON.
    ///
    /// Accepts the JSON output of `tpm audit publish` (piped or from
    /// a file) and inserts it into the witness log. Useful when
    /// submitting to an air-gapped or manual witness service.
    Record {
        /// Path to the witness submission JSON file (use `-` for stdin).
        #[arg(long, default_value = "-")]
        input: String,
    },
    /// Garbage-collect old witness receipts, keeping only the most
    /// recent N receipts per stream (and/or those newer than a cutoff).
    ///
    /// At least one of --keep-latest or --older-than must be given.
    Gc {
        /// Stream name to GC (or "all" to GC every stream).
        #[arg(long, default_value = "all")]
        stream: String,
        /// Keep at most N most-recent receipts per stream.
        #[arg(long)]
        keep_latest: Option<usize>,
        /// Delete receipts received before this RFC 3339 timestamp
        /// (e.g. 2026-01-01T00:00:00Z).
        #[arg(long)]
        older_than: Option<String>,
        /// Print what would be deleted without actually deleting.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum AuditStreamsCommand {
    /// List all declared streams with their confidentiality tiers.
    List,
    /// Create a new stream.
    Create {
        /// Stream name (alphanumeric + dash/underscore recommended).
        name: String,
        /// Confidentiality tier.
        /// One of: public, protected, highly-restricted.
        #[arg(long, default_value = "public")]
        tier: String,
        /// Optional human-readable description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Show a single stream's metadata.
    Show {
        name: String,
    },
    /// Change a stream's confidentiality tier.
    SetTier {
        name: String,
        #[arg(long)]
        tier: String,
    },
    /// Deprecate a stream, preventing new entries from being appended.
    ///
    /// Existing entries and segments remain intact and verifiable.
    /// The stream row is preserved so history and witness records stay accessible.
    Delete {
        /// Stream name.
        name: String,
    },
}

#[derive(Subcommand)]
pub enum AuditKeyCommand {
    /// Generate a new random master KEK and save it to the given path.
    ///
    /// By default the key is sealed under a TPM-protected key via
    /// `backend.seal`; pass `--plaintext` to store it as raw 32 bytes
    /// with 0600 permissions (useful for mock/test backends).
    Init {
        /// Path to write the KEK file to.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Store the KEK unsealed (raw 32 bytes) instead of wrapped
        /// by the TPM backend.
        #[arg(long)]
        plaintext: bool,
    },
    /// Show the path used by subsequent audit commands, plus whether
    /// the on-disk format is sealed or plaintext.
    Show,
}

#[derive(Subcommand)]
pub enum AuditSegmentsCommand {
    /// Close the currently-open window and build its Merkle root.
    Close {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// List all closed segments.
    List {
        #[arg(long, default_value = "default")]
        stream: String,
    },
    /// Show a single segment by id.
    Show {
        segment_id: u64,
    },
}

#[derive(Subcommand)]
pub enum AuditChainCommand {
    /// Walk the hash chain and verify every link.
    Verify {
        /// Start seqno (default 1).
        #[arg(long, default_value = "1")]
        from: u64,
        /// End seqno (default: current head).
        #[arg(long)]
        to: Option<u64>,
        /// Target stream.
        #[arg(long, default_value = "default")]
        stream: String,
    },
}

#[derive(Subcommand)]
pub enum IdentityCommand {
    /// Initialize a new identity (creates backing key)
    Init {
        /// Identity name
        name: String,
        /// Intended usage (code-signing, tls, ssh, attestation, generic)
        #[arg(long, default_value = "generic")]
        usage: String,
        /// Key algorithm
        #[arg(long, default_value = "ecc-p256")]
        algorithm: String,
        /// Attach a named policy
        #[arg(long)]
        policy: Option<String>,
        /// Certificate subject (e.g. "CN=Release Signer")
        #[arg(long)]
        subject: Option<String>,
        /// Override backing key path (default: signing/<name>)
        #[arg(long)]
        key_path: Option<String>,
    },
    /// Show identity details
    Show {
        /// Identity name
        name: String,
    },
    /// List all identities
    List,
    /// Rotate an identity's backing key
    Rotate {
        /// Identity name
        name: String,
    },
    /// Delete an identity
    Delete {
        /// Identity name
        name: String,
        /// Also delete the underlying key object
        #[arg(long)]
        cascade: bool,
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

#[derive(Subcommand)]
pub enum VtpmCommand {
    /// Provision a credential: hw-TPM signs an endorsement statement for the vTPM
    Provision {
        /// Hardware backend to provision against (`device` or `swtpm`)
        #[arg(long, default_value = "device")]
        hw_backend: String,
        /// Path to write the credential file (defaults to $XDG_DATA_HOME/tpm/vtpm-credential.json)
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Free-form vTPM label baked into the signed identity
        #[arg(long)]
        label: Option<String>,
    },
    /// Inspect or verify an existing credential
    #[command(subcommand)]
    Credential(VtpmCredentialCommand),
}

#[derive(Subcommand)]
pub enum VtpmCredentialCommand {
    /// Print credential metadata (offline)
    Show {
        /// Path to the credential file
        #[arg(long)]
        path: Option<std::path::PathBuf>,
    },
    /// Verify the credential signature against the hardware TPM
    Verify {
        /// Hardware backend to verify against (`device` or `swtpm`)
        #[arg(long, default_value = "device")]
        hw_backend: String,
        /// Path to the credential file
        #[arg(long)]
        path: Option<std::path::PathBuf>,
    },
}
