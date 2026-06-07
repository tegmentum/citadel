//! swtpm simulator lifecycle management.
//!
//! Manages a local [`swtpm`](https://github.com/stefanberger/swtpm) process —
//! a full software TPM 2.0 (libtpms). Unlike the in-process vTPM component,
//! this drives the *real* `swtpm` daemon, which is what QEMU needs as its TPM
//! device for measured-boot event-log capture (the A1 lab), and what gives a
//! persistent TPM that signs for real.
//!
//! `SwtpmManager` owns the process and exposes its two unix sockets:
//! * **control** (`--ctrl`) — power-on/reset/state commands;
//! * **data/server** (`--server`) — the TPM command channel QEMU (or a client)
//!   talks TPM2 over.
//!
//! Pure process management: no `tpm-hw` feature and no extra deps; it self-skips
//! gracefully when the `swtpm` binary is absent (see [`SwtpmManager::is_available`]).

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Default state directory for an unnamed manager.
const DEFAULT_STATE_DIR: &str = "/tmp/citadel-swtpm-state";

/// Manages a `swtpm` TPM 2.0 simulator process.
pub struct SwtpmManager {
    state_dir: PathBuf,
    ctrl_path: PathBuf,
    server_path: PathBuf,
    process: Option<Child>,
}

impl SwtpmManager {
    /// Create a manager rooted at `state_dir` (TPM NV/PCR state persists there
    /// across runs); `None` uses a default temp location.
    pub fn new(state_dir: Option<&Path>) -> Self {
        let state_dir = state_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
        let ctrl_path = state_dir.join("swtpm-ctrl.sock");
        let server_path = state_dir.join("swtpm-server.sock");
        Self {
            state_dir,
            ctrl_path,
            server_path,
            process: None,
        }
    }

    /// The control socket (`--ctrl`) — power-on/reset/state.
    pub fn ctrl_socket_path(&self) -> &Path {
        &self.ctrl_path
    }

    /// The data/server socket (`--server`) — the TPM2 command channel (point
    /// QEMU's `chardev socket` at this).
    pub fn server_socket_path(&self) -> &Path {
        &self.server_path
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Whether the `swtpm` binary is installed.
    pub fn is_available() -> bool {
        Command::new("swtpm")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Start the simulator with both control and data sockets. State persists
    /// in `state_dir`; the TPM powers on clean (`startup-clear`).
    pub fn start(&mut self) -> anyhow::Result<()> {
        if self.process.is_some() {
            anyhow::bail!("swtpm already running");
        }
        if !Self::is_available() {
            anyhow::bail!("swtpm binary not found on PATH (install: `brew install swtpm`)");
        }
        std::fs::create_dir_all(&self.state_dir)?;
        // Stale sockets from a previous run would block bind.
        let _ = std::fs::remove_file(&self.ctrl_path);
        let _ = std::fs::remove_file(&self.server_path);

        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={}", self.state_dir.display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={}", self.ctrl_path.display()))
            .arg("--server")
            .arg(format!("type=unixio,path={}", self.server_path.display()))
            .arg("--flags")
            .arg("startup-clear")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        self.process = Some(child);

        // Wait for the data socket to appear (up to ~2s).
        for _ in 0..40 {
            if self.server_path.exists() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Clean up the half-started process before surfacing the error.
        self.stop().ok();
        anyhow::bail!(
            "swtpm started but its server socket did not appear at {}",
            self.server_path.display()
        )
    }

    /// Stop the simulator and remove its sockets.
    pub fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.process.take() {
            child.kill().ok();
            child.wait().ok();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
        let _ = std::fs::remove_file(&self.server_path);
        Ok(())
    }

    /// Whether the simulator process is currently running.
    pub fn is_running(&self) -> bool {
        self.process.is_some() && self.server_path.exists()
    }

    /// A status snapshot (for diagnostics / `tpm` CLI).
    pub fn status(&self) -> SwtpmStatus {
        SwtpmStatus {
            installed: Self::is_available(),
            running: self.is_running(),
            ctrl_socket: self.ctrl_path.display().to_string(),
            server_socket: self.server_path.display().to_string(),
            state_dir: self.state_dir.display().to_string(),
        }
    }
}

impl Drop for SwtpmManager {
    fn drop(&mut self) {
        self.stop().ok();
    }
}

/// Diagnostic status of a managed swtpm.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SwtpmStatus {
    pub installed: bool,
    pub running: bool,
    pub ctrl_socket: String,
    pub server_socket: String,
    pub state_dir: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_derived_from_state_dir() {
        let dir = std::env::temp_dir().join("citadel-swtpm-unit");
        let m = SwtpmManager::new(Some(&dir));
        assert_eq!(m.state_dir(), dir.as_path());
        assert!(m.ctrl_socket_path().starts_with(&dir));
        assert!(m.server_socket_path().starts_with(&dir));
        assert!(!m.is_running(), "not running before start");
    }

    #[test]
    fn start_stop_roundtrip_when_swtpm_present() {
        if !SwtpmManager::is_available() {
            eprintln!("skipping: swtpm binary not on PATH (`brew install swtpm`)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("citadel-swtpm-{}", std::process::id()));
        let mut m = SwtpmManager::new(Some(&dir));
        m.start().expect("swtpm starts");
        assert!(m.is_running());
        assert!(m.server_socket_path().exists());
        m.stop().expect("swtpm stops");
        assert!(!m.is_running());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
