use tpm_core::backend::SwtpmManager;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;

use serde::Serialize;

pub fn start(state_dir: Option<&str>, format: OutputFormat) -> anyhow::Result<()> {
    if !SwtpmManager::is_available() {
        anyhow::bail!(
            "swtpm is not installed.\n\
             Install it with your package manager:\n\
             - Debian/Ubuntu: apt install swtpm\n\
             - Fedora: dnf install swtpm\n\
             - macOS: brew install swtpm"
        );
    }

    let mut mgr = SwtpmManager::new(state_dir.map(std::path::Path::new));

    if mgr.is_running() {
        println!("swtpm already running at {}", mgr.socket_path().display());
        return Ok(());
    }

    mgr.start()?;

    let result = SimStarted {
        socket_path: mgr.socket_path().display().to_string(),
        state_dir: mgr.state_dir().display().to_string(),
    };
    println!("{}", render(&result, format));

    // Leak the manager so it doesn't kill the process on drop
    std::mem::forget(mgr);

    Ok(())
}

pub fn stop(state_dir: Option<&str>) -> anyhow::Result<()> {
    let mut mgr = SwtpmManager::new(state_dir.map(std::path::Path::new));
    if !mgr.is_running() {
        println!("swtpm is not running");
        return Ok(());
    }
    mgr.stop()?;
    println!("swtpm stopped");
    Ok(())
}

pub fn status(state_dir: Option<&str>, format: OutputFormat) -> anyhow::Result<()> {
    let mgr = SwtpmManager::new(state_dir.map(std::path::Path::new));
    let status = mgr.status();

    let result = SimStatus {
        installed: status.installed,
        running: status.running,
        socket_path: status.socket_path,
        state_dir: status.state_dir,
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct SimStarted {
    socket_path: String,
    state_dir: String,
}

impl TextRenderable for SimStarted {
    fn render_text(&self) -> String {
        format!(
            "swtpm simulator started\n  socket: {}\n  state:  {}\n\n\
             use with: tpm --backend swtpm <command>\n",
            self.socket_path, self.state_dir
        )
    }
}

#[derive(Serialize)]
struct SimStatus {
    installed: bool,
    running: bool,
    socket_path: String,
    state_dir: String,
}

impl TextRenderable for SimStatus {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("swtpm simulator\n");
        out.push_str(&format!(
            "  installed: {}\n",
            if self.installed { "yes" } else { "no" }
        ));
        out.push_str(&format!(
            "  running:   {}\n",
            if self.running { "yes" } else { "no" }
        ));
        out.push_str(&format!("  socket:    {}\n", self.socket_path));
        out.push_str(&format!("  state:     {}\n", self.state_dir));
        out
    }
}
