//! Smoke tests against the real libtpms vTPM backend.
//!
//! These tests require:
//! - Build with `--features vtpm`
//! - TPM_VTPM_COMPONENT env var pointing to tpm-ephemeral.component.wasm
//!
//! Get the component from a local libtpms-wasm build
//! (`~/git/libtpms-wasm/dist/tpm-ephemeral.component.wasm`) or download
//! the published one:
//!   curl -fsSL -o /tmp/tpm-ephemeral.component.wasm \
//!     https://github.com/tegmentum/libtpms-wasm/releases/latest/download/tpm-ephemeral.component.wasm
//!
//! Run:
//!   TPM_VTPM_COMPONENT=/tmp/tpm-ephemeral.component.wasm \
//!     cargo test --features vtpm --test vtpm_smoke

use std::process::Command;

fn vtpm_component() -> Option<String> {
    std::env::var("TPM_VTPM_COMPONENT").ok()
}

fn tpm_vtpm(store: &std::path::Path) -> Command {
    let component = vtpm_component().expect(
        "TPM_VTPM_COMPONENT not set — point it at tpm-ephemeral.component.wasm",
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tpm"));
    cmd.env("TPM_STORE_PATH", store);
    cmd.env("TPM_VTPM_COMPONENT", &component);
    cmd.env("NO_COLOR", "1");
    cmd.args(["--backend", "vtpm"]);
    cmd
}

fn run(cmd: &mut Command) -> (String, String, bool) {
    let output = cmd.output().expect("failed to execute tpm");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

fn assert_ok(cmd: &mut Command) -> String {
    let (stdout, stderr, ok) = run(cmd);
    assert!(ok, "command failed:\nstdout: {}\nstderr: {}", stdout, stderr);
    stdout
}

fn skip_if_no_component() -> bool {
    vtpm_component().is_none()
}

// ─── Basic vTPM connectivity ────────────────────────────────────

#[test]
fn vtpm_status() {
    if skip_if_no_component() {
        eprintln!("skipping: TPM_VTPM_COMPONENT not set");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    let out = assert_ok(tpm_vtpm(&store).args(["status"]));
    assert!(out.contains("vtpm"));
    assert!(out.contains("available:    yes") || out.contains("available: true"));
}

#[test]
fn vtpm_doctor() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    let out = assert_ok(tpm_vtpm(&store).args(["doctor"]));
    assert!(out.contains("[ok]") || out.contains("healthy"));
}

// ─── PCR reads return real TPM state ────────────────────────────

#[test]
fn vtpm_pcr_read() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    let out = assert_ok(tpm_vtpm(&store).args(["pcr", "show", "--index", "0,7"]));
    assert!(out.contains("PCR bank: sha256"));
    // Fresh vTPM should have all-zero PCRs
    assert!(out.contains("0000000000000000"));
}

#[test]
fn vtpm_pcr_json() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    let out = assert_ok(
        tpm_vtpm(&store).args(["pcr", "show", "--index", "0,7", "--format", "json"]),
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["bank"], "sha256");
    assert!(parsed["values"].is_array());
    assert_eq!(parsed["values"].as_array().unwrap().len(), 2);
}

// ─── Key lifecycle on vTPM ──────────────────────────────────────

#[test]
fn vtpm_key_lifecycle() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    // Init
    let out = assert_ok(tpm_vtpm(&store).args(["init"]));
    assert!(out.contains("initialized"));

    // Create key
    let out = assert_ok(tpm_vtpm(&store).args(["key", "create", "signing/vtpm-key"]));
    assert!(out.contains("key created"));

    // List
    let out = assert_ok(tpm_vtpm(&store).args(["key", "list"]));
    assert!(out.contains("signing/vtpm-key"));

    // Show
    let out = assert_ok(tpm_vtpm(&store).args(["key", "show", "signing/vtpm-key"]));
    assert!(out.contains("signing/vtpm-key"));
    assert!(out.contains("handle:     present"));

    // Sign (uses TPM2_GetRandom internally)
    let artifact = dir.path().join("data.bin");
    std::fs::write(&artifact, b"test data for vtpm signing").unwrap();
    let out = assert_ok(
        tpm_vtpm(&store)
            .args(["key", "sign", "signing/vtpm-key", "--input"])
            .arg(&artifact),
    );
    assert!(out.contains("signed with"));
    assert!(out.contains("signature:"));

    // Delete
    let out = assert_ok(tpm_vtpm(&store).args(["key", "delete", "signing/vtpm-key"]));
    assert!(out.contains("deleted"));
}

// ─── PCR baseline with real values ──────────────────────────────

#[test]
fn vtpm_pcr_baseline() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    assert_ok(tpm_vtpm(&store).args(["init"]));

    // Save baseline
    let out = assert_ok(
        tpm_vtpm(&store).args(["pcr", "baseline", "save", "fresh-boot", "--index", "0,7,11"]),
    );
    assert!(out.contains("baseline saved"));
    assert!(out.contains("PCRs: 3"));

    // Diff should match (same vTPM state)
    let out = assert_ok(tpm_vtpm(&store).args(["pcr", "baseline", "diff", "fresh-boot"]));
    assert!(out.contains("match"));
}

// ─── Full workflow: init → key → sign → export ──────────────────

#[test]
fn vtpm_full_workflow() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    // Init workspace
    assert_ok(tpm_vtpm(&store).args(["init"]));

    // Create policy
    assert_ok(tpm_vtpm(&store).args(["policy", "create", "boot", "--pcr", "7"]));

    // Create key with policy
    assert_ok(
        tpm_vtpm(&store).args(["key", "create", "signing/release", "--policy", "boot"]),
    );

    // Sign an artifact
    let artifact = dir.path().join("release.tar.gz");
    std::fs::write(&artifact, b"release artifact contents").unwrap();
    assert_ok(
        tpm_vtpm(&store)
            .args(["key", "sign", "signing/release", "--input"])
            .arg(&artifact),
    );

    // Export public key
    let out = assert_ok(
        tpm_vtpm(&store).args(["key", "export-pub", "signing/release", "--export-for", "openssl"]),
    );
    assert!(out.contains("PUBLIC KEY"));

    // Object tree
    let out = assert_ok(tpm_vtpm(&store).args(["object", "tree"]));
    assert!(out.contains("signing/release"));
    assert!(out.contains("policies/"));
    assert!(out.contains("boot"));

    // Status with health
    let out = assert_ok(tpm_vtpm(&store).args(["status"]));
    assert!(out.contains("Health:"));
    assert!(out.contains("vtpm"));

    // Audit log
    let out = assert_ok(tpm_vtpm(&store).args(["log", "show"]));
    assert!(out.contains("key.create"));
    assert!(out.contains("key.sign"));
}

// ─── Capabilities from real vTPM ────────────────────────────────

#[test]
fn vtpm_capabilities() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    let out = assert_ok(tpm_vtpm(&store).args(["capabilities"]));
    assert!(out.contains("vtpm"));
    assert!(out.contains("libtpms"));
}

// ─── JSON output from vTPM ──────────────────────────────────────

#[test]
fn vtpm_json_output() {
    if skip_if_no_component() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("vtpm.db");

    assert_ok(tpm_vtpm(&store).args(["init"]));
    assert_ok(tpm_vtpm(&store).args(["key", "create", "signing/json"]));

    let out = assert_ok(tpm_vtpm(&store).args(["status", "--format", "json"]));
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["backend"]["backend_type"], "vtpm");

    let out = assert_ok(tpm_vtpm(&store).args(["key", "list", "--format", "json"]));
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(parsed["keys"].is_array());
}
