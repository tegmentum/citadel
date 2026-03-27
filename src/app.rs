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
    /// Key management
    #[command(subcommand)]
    Key(KeyCommand),
    /// Profile management
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Daemon management
    #[command(subcommand)]
    Daemon(DaemonCommand),
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
