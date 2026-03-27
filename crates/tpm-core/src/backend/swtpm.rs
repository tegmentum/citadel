//! swtpm simulator management.
//!
//! This module manages a local swtpm process for development and testing.
//! It does not require the tpm-hw feature — it manages the simulator process
//! and provides a mock-like backend that delegates to swtpm when available.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// State directory for swtpm.
const DEFAULT_STATE_DIR: &str = "/tmp/tpm-swtpm-state";

/// Manages a swtpm simulator process.
pub struct SwtpmManager {
    state_dir: PathBuf,
    socket_path: PathBuf,
    process: Option<Child>,
}

impl SwtpmManager {
    pub fn new(state_dir: Option<&Path>) -> Self {
        let state_dir = state_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
        let socket_path = state_dir.join("swtpm-sock");
        Self {
            state_dir,
            socket_path,
            process: None,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Check if swtpm is installed.
    pub fn is_available() -> bool {
        Command::new("swtpm")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Start the swtpm simulator.
    pub fn start(&mut self) -> anyhow::Result<()> {
        if self.process.is_some() {
            anyhow::bail!("swtpm already running");
        }

        std::fs::create_dir_all(&self.state_dir)?;

        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpmstate")
            .arg(format!("dir={}", self.state_dir.display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={}", self.socket_path.display()))
            .arg("--tpm2")
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .arg("--log")
            .arg("level=0")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        self.process = Some(child);

        // Wait briefly for socket to appear
        for _ in 0..20 {
            if self.socket_path.exists() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        anyhow::bail!(
            "swtpm started but socket not found at {} after 2s",
            self.socket_path.display()
        )
    }

    /// Stop the swtpm simulator.
    pub fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.process.take() {
            child.kill().ok();
            child.wait().ok();
        }
        // Also clean up socket
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).ok();
        }
        Ok(())
    }

    /// Check if the simulator is running.
    pub fn is_running(&self) -> bool {
        self.socket_path.exists()
    }

    /// Get status information.
    pub fn status(&self) -> SwtpmStatus {
        SwtpmStatus {
            installed: Self::is_available(),
            running: self.is_running(),
            socket_path: self.socket_path.display().to_string(),
            state_dir: self.state_dir.display().to_string(),
        }
    }
}

impl Drop for SwtpmManager {
    fn drop(&mut self) {
        self.stop().ok();
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SwtpmStatus {
    pub installed: bool,
    pub running: bool,
    pub socket_path: String,
    pub state_dir: String,
}
