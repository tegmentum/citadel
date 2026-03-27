//! CLI integration tests.
//!
//! These tests run the `tpm` binary as a subprocess and verify output.
//! Each test gets its own temporary store to avoid interference.

use std::process::Command;

fn tpm_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tpm"));
    // Each test gets a unique temp store
    let store = tempfile::NamedTempFile::new().unwrap();
    cmd.env("TPM_STORE_PATH", store.path());
    cmd.env("NO_COLOR", "1");
    cmd
}

fn tpm_cmd_with_store(store_path: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tpm"));
    cmd.env("TPM_STORE_PATH", store_path);
    cmd.env("NO_COLOR", "1");
    cmd
}

fn run(cmd: &mut Command) -> (String, String, bool) {
    let output = cmd.output().expect("failed to execute tpm");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

// === Basic commands ===

#[test]
fn help_output() {
    let (stdout, _, ok) = run(tpm_cmd().arg("--help"));
    assert!(ok);
    assert!(stdout.contains("TPM operator platform"));
    assert!(stdout.contains("key"));
    assert!(stdout.contains("secret"));
    assert!(stdout.contains("attest"));
}

#[test]
fn version_output() {
    let (stdout, _, ok) = run(tpm_cmd().arg("--version"));
    assert!(ok);
    assert!(stdout.contains("tpm"));
}

#[test]
fn init_creates_workspace() {
    let store = tempfile::NamedTempFile::new().unwrap();
    let (stdout, _, ok) = run(tpm_cmd_with_store(store.path()).arg("init"));
    assert!(ok);
    assert!(stdout.contains("workspace initialized"));
    assert!(stdout.contains("default"));
}

#[test]
fn init_idempotent() {
    let store = tempfile::NamedTempFile::new().unwrap();
    run(tpm_cmd_with_store(store.path()).arg("init"));
    let (stdout, _, ok) = run(tpm_cmd_with_store(store.path()).arg("init"));
    assert!(ok);
    assert!(stdout.contains("already initialized"));
}

// === Key lifecycle ===

#[test]
fn key_create_list_show_delete() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    // Create
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "create", "signing/test"]));
    assert!(ok);
    assert!(stdout.contains("key created: signing/test"));
    assert!(stdout.contains("ecc-p256"));

    // List
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["key", "list"]));
    assert!(ok);
    assert!(stdout.contains("signing/test"));

    // Show
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "show", "signing/test"]));
    assert!(ok);
    assert!(stdout.contains("path:"));
    assert!(stdout.contains("signing/test"));
    assert!(stdout.contains("signing key"));

    // Delete
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "delete", "signing/test"]));
    assert!(ok);
    assert!(stdout.contains("key deleted"));

    // Verify gone
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["key", "list"]));
    assert!(ok);
    assert!(stdout.contains("No keys found"));
}

#[test]
fn key_create_duplicate_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/dup"]));
    let (_, stderr, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "create", "signing/dup"]));
    assert!(!ok);
    assert!(stderr.contains("TPM0007") || stderr.contains("already exists"));
}

#[test]
fn key_show_nonexistent_fails() {
    let (_, stderr, ok) = run(tpm_cmd().args(["key", "show", "signing/nope"]));
    assert!(!ok);
    assert!(stderr.contains("TPM0004") || stderr.contains("not found"));
}

// === JSON output ===

#[test]
fn json_output_valid() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/json-test"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "list", "--format", "json"]));
    assert!(ok);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"][0]["path"], "signing/json-test");
}

#[test]
fn status_json() {
    let (stdout, _, ok) = run(tpm_cmd().args(["status", "--format", "json"]));
    assert!(ok);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["backend"]["backend_type"], "mock");
    assert_eq!(parsed["backend"]["available"], true);
}

// === Policy ===

#[test]
fn policy_create_list_delete() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["policy", "create", "boot", "--pcr", "7,11"]));
    assert!(ok);
    assert!(stdout.contains("policy created: boot"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["policy", "list"]));
    assert!(ok);
    assert!(stdout.contains("boot"));
    assert!(stdout.contains("sha256:7,11"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["policy", "delete", "boot"]));
    assert!(ok);
    assert!(stdout.contains("deleted"));
}

// === Secret seal/unseal ===

#[test]
fn secret_seal_unseal() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let secret_file = dir.path().join("secret.txt");
    std::fs::write(&secret_file, "super-secret-value").unwrap();

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["secret", "seal", "db/pass", "--input"])
        .arg(&secret_file));
    assert!(ok);
    assert!(stdout.contains("secret sealed: db/pass"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["secret", "unseal", "db/pass"]));
    assert!(ok);
    assert!(stdout.contains("super-secret-value"));
}

// === Attestation ===

#[test]
fn attestation_flow() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let quote_file = dir.path().join("quote.json");

    // Create AK
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["attest", "ak-create", "attest/main"]));
    assert!(ok);
    assert!(stdout.contains("attestation key created"));

    // Generate quote
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args([
            "attest", "quote",
            "--ak", "attest/main",
            "--pcr", "0,7",
            "--nonce", "test-challenge",
            "--output",
        ])
        .arg(&quote_file));
    assert!(ok);
    assert!(stdout.contains("quote generated"));

    // Verify quote
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["attest", "verify", "--quote"])
        .arg(&quote_file)
        .args(["--nonce", "test-challenge"]));
    assert!(ok);
    assert!(stdout.contains("VERIFIED"));
}

// === Object tree ===

#[test]
fn object_tree() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let secret_file = dir.path().join("s.txt");
    std::fs::write(&secret_file, "x").unwrap();

    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/a"]));
    run(tpm_cmd_with_store(&store)
        .args(["secret", "seal", "secret/b", "--input"])
        .arg(&secret_file));
    run(tpm_cmd_with_store(&store)
        .args(["policy", "create", "pol", "--pcr", "7"]));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["object", "tree"]));
    assert!(ok);
    assert!(stdout.contains("keys/"));
    assert!(stdout.contains("signing/a"));
    assert!(stdout.contains("secrets/"));
    assert!(stdout.contains("secret/b"));
    assert!(stdout.contains("policies/"));
    assert!(stdout.contains("pol"));
}

// === Doctor ===

#[test]
fn doctor_healthy() {
    let (stdout, _, ok) = run(tpm_cmd().args(["doctor"]));
    assert!(ok);
    assert!(stdout.contains("healthy") || stdout.contains("[ok]"));
}

// === Status with health ===

#[test]
fn status_shows_health() {
    let (stdout, _, ok) = run(tpm_cmd().args(["status"]));
    assert!(ok);
    assert!(stdout.contains("Health:"));
}

// === Explain ===

#[test]
fn explain_pcr() {
    let (stdout, _, ok) = run(tpm_cmd().args(["explain", "pcr"]));
    assert!(ok);
    assert!(stdout.contains("Platform Configuration Registers"));
}

// === Templates ===

#[test]
fn template_list() {
    let (stdout, _, ok) = run(tpm_cmd().args(["template", "list"]));
    assert!(ok);
    assert!(stdout.contains("signing-key"));
    assert!(stdout.contains("ci-signer"));
}

// === Plan mode ===

#[test]
fn plan_mode_no_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["--plan", "key", "create", "signing/planned"]));
    assert!(ok);
    assert!(stdout.contains("plan:"));
    assert!(stdout.contains("no changes made"));

    // Key should NOT exist
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["key", "list"]));
    assert!(ok);
    assert!(stdout.contains("No keys found"));
}

// === Recover ===

#[test]
fn recover_list_and_show() {
    let (stdout, _, ok) = run(tpm_cmd().args(["recover", "list"]));
    assert!(ok);
    assert!(stdout.contains("tpm-cleared"));

    let (stdout, _, ok) = run(tpm_cmd().args(["recover", "show", "boot-change"]));
    assert!(ok);
    assert!(stdout.contains("steps:"));
    assert!(stdout.contains("pcr"));
}

// === Capabilities ===

#[test]
fn capabilities_output() {
    let (stdout, _, ok) = run(tpm_cmd().args(["capabilities"]));
    assert!(ok);
    assert!(stdout.contains("ecc-p256"));
    assert!(stdout.contains("sha256"));
}

// === Invalid path ===

#[test]
fn invalid_path_good_error() {
    let (_, stderr, ok) = run(tpm_cmd().args(["key", "show", "bad path!"]));
    assert!(!ok);
    assert!(stderr.contains("TPM0003") || stderr.contains("invalid"));
}

// === Key rotation ===

#[test]
fn key_rotate() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/rot"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "rotate", "signing/rot"]));
    assert!(ok);
    assert!(stdout.contains("key rotated"));
    assert!(stdout.contains("archived"));

    // Original name should still exist (new key)
    let (stdout, _, _) = run(tpm_cmd_with_store(&store)
        .args(["key", "show", "signing/rot"]));
    assert!(stdout.contains("signing/rot"));
}

// === GC ===

#[test]
fn gc_after_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/gc"]));
    run(tpm_cmd_with_store(&store).args(["key", "rotate", "signing/gc"]));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["gc", "plan"]));
    assert!(ok);
    assert!(stdout.contains("1 candidate"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["gc", "apply"]));
    assert!(ok);
    assert!(stdout.contains("1 object(s) removed"));
}

// === Export ===

#[test]
fn key_export_pub_formats() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/exp"]));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "export-pub", "signing/exp", "--export-for", "ssh"]));
    assert!(ok);
    assert!(stdout.contains("ssh-"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["key", "export-pub", "signing/exp", "--export-for", "pkcs11"]));
    assert!(ok);
    assert!(stdout.contains("pkcs11:"));
}
