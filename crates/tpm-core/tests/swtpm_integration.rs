//! swtpm integration test.
//!
//! Requires build with `--features tpm-hw` AND the `swtpm` binary on PATH.
//! When either is missing, every test in this file self-skips.
//!
//! Run:
//!   cargo test --features tpm-hw --test swtpm_integration

#![cfg(feature = "tpm-hw")]

use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tpm_core::backend::{HardwareBackend, TpmBackend};
use tpm_core::model::{Algorithm, ObjectPath};

/// Returns true if the `swtpm` binary is available on PATH.
fn swtpm_available() -> bool {
    Command::new("swtpm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Pick a free TCP port by binding to 0, reading the assigned port, and
/// releasing the socket. Racy in principle, fine in practice for tests.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Wait until a TCP port accepts connections, up to `timeout`.
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Handle that kills swtpm when dropped.
struct SwtpmGuard {
    child: Child,
    _tmpdir: tempfile::TempDir,
}

impl Drop for SwtpmGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_swtpm(server_port: u16, ctrl_port: u16) -> SwtpmGuard {
    let tmpdir = tempfile::tempdir().unwrap();
    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--server",
            &format!("type=tcp,port={}", server_port),
            "--ctrl",
            &format!("type=tcp,port={}", ctrl_port),
            "--tpmstate",
            &format!("dir={}", tmpdir.path().display()),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn swtpm");
    SwtpmGuard {
        child,
        _tmpdir: tmpdir,
    }
}

#[test]
fn swtpm_tcp_status_and_create_key() {
    if !swtpm_available() {
        eprintln!("swtpm not on PATH, skipping");
        return;
    }

    let server_port = free_port();
    let ctrl_port = free_port();
    let _guard = start_swtpm(server_port, ctrl_port);

    assert!(
        wait_for_port(server_port, Duration::from_secs(3)),
        "swtpm did not start listening on port {} within 3s",
        server_port
    );

    let backend = HardwareBackend::new_swtpm_tcp("localhost", server_port)
        .expect("HardwareBackend::new_swtpm_tcp");

    let status = backend.status().expect("backend.status()");
    assert!(status.available);
    assert_eq!(status.backend_type, "swtpm");

    // Create a key and sign something.
    let path = ObjectPath::new("signing/swtpm-test").unwrap();
    let handle = backend
        .create_key(Algorithm::EccP256, &path)
        .expect("create_key");
    assert!(!handle.id.is_empty());

    let sig = backend.sign(&handle, b"hello world").expect("sign");
    assert!(!sig.is_empty());
}

#[test]
fn swtpm_tcp_pcr_read() {
    if !swtpm_available() {
        eprintln!("swtpm not on PATH, skipping");
        return;
    }

    let server_port = free_port();
    let ctrl_port = free_port();
    let _guard = start_swtpm(server_port, ctrl_port);

    assert!(wait_for_port(server_port, Duration::from_secs(3)));

    let backend =
        HardwareBackend::new_swtpm_tcp("localhost", server_port).unwrap();

    let pcrs = backend
        .pcr_read("sha256", &[0, 7])
        .expect("pcr_read sha256:0,7");
    assert_eq!(pcrs.len(), 2);
    assert_eq!(pcrs[0].index, 0);
    assert_eq!(pcrs[1].index, 7);
    assert_eq!(pcrs[0].bank, "sha256");
    // sha256 digest is 32 bytes
    assert_eq!(pcrs[0].digest.len(), 32);
}
