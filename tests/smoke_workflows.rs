//! End-to-end workflow smoke tests.
//!
//! These exercise realistic multi-step operator scenarios through
//! the CLI binary, verifying that the full pipeline works together.

use std::process::Command;

fn tpm(store: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_citadel"));
    cmd.env("TPM_STORE_PATH", store);
    cmd.env("NO_COLOR", "1");
    cmd.arg("tpm");
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
    assert!(
        ok,
        "command failed:\nstdout: {}\nstderr: {}",
        stdout, stderr
    );
    stdout
}

fn assert_fail(cmd: &mut Command) -> String {
    let (stdout, stderr, ok) = run(cmd);
    assert!(!ok, "expected failure but succeeded:\n{}", stdout);
    stderr
}

// ─── Workflow 1: CI signing setup ───────────────────────────────

#[test]
fn workflow_ci_signing() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("ci.db");
    let artifact = dir.path().join("artifact.bin");
    let sig = dir.path().join("artifact.sig");
    std::fs::write(&artifact, b"release-build-v1.0.0-sha256:abcdef").unwrap();

    // Initialize workspace
    let out = assert_ok(tpm(&store).arg("init"));
    assert!(out.contains("workspace initialized"));

    // Create a release signing key
    let out = assert_ok(tpm(&store).args(["key", "create", "signing/release"]));
    assert!(out.contains("key created"));

    // Create a dev signing key
    assert_ok(tpm(&store).args(["key", "create", "signing/dev"]));

    // List keys — should have 2
    let out = assert_ok(tpm(&store).args(["key", "list"]));
    assert!(out.contains("signing/dev"));
    assert!(out.contains("signing/release"));

    // Sign the artifact
    let out = assert_ok(
        tpm(&store)
            .args(["key", "sign", "signing/release", "--input"])
            .arg(&artifact)
            .args(["--output"])
            .arg(&sig),
    );
    assert!(out.contains("signed with"));
    assert!(sig.exists());

    // Export public key for verification
    let out = assert_ok(tpm(&store).args([
        "key",
        "export-pub",
        "signing/release",
        "--export-for",
        "cosign",
    ]));
    assert!(out.contains("BEGIN PUBLIC KEY"));
    assert!(out.contains("cosign verify"));

    // Check audit trail
    let out = assert_ok(tpm(&store).args(["log", "show"]));
    assert!(out.contains("key.create"));
    assert!(out.contains("key.sign"));

    // Rotate the release key
    let out = assert_ok(tpm(&store).args(["key", "rotate", "signing/release"]));
    assert!(out.contains("key rotated"));
    assert!(out.contains("archived"));

    // GC the old key
    let out = assert_ok(tpm(&store).args(["gc", "plan"]));
    assert!(out.contains("1 candidate"));
    assert_ok(tpm(&store).args(["gc", "apply"]));

    // Verify the tree is clean
    let out = assert_ok(tpm(&store).args(["object", "tree"]));
    assert!(out.contains("signing/release"));
    assert!(out.contains("signing/dev"));
}

// ─── Workflow 2: Secret management with policies ────────────────

#[test]
fn workflow_secret_management() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("secrets.db");
    let secret_file = dir.path().join("dbpass.txt");
    std::fs::write(&secret_file, "postgres://admin:s3cret@db:5432/prod").unwrap();

    assert_ok(tpm(&store).arg("init"));

    // Create a boot policy
    let out = assert_ok(tpm(&store).args(["policy", "create", "boot-seal", "--pcr", "7,11"]));
    assert!(out.contains("policy created"));

    // Seal a secret with the policy
    let out = assert_ok(
        tpm(&store)
            .args(["secret", "seal", "db/prod-password", "--input"])
            .arg(&secret_file)
            .args(["--policy", "boot-seal"]),
    );
    assert!(out.contains("secret sealed"));
    assert!(out.contains("policy: yes"));

    // List secrets
    let out = assert_ok(tpm(&store).args(["secret", "list"]));
    assert!(out.contains("db/prod-password"));

    // Unseal it
    let out = assert_ok(tpm(&store).args(["secret", "unseal", "db/prod-password"]));
    assert!(out.contains("postgres://admin:s3cret@db:5432/prod"));

    // Check object list shows the sealed secret
    let out = assert_ok(tpm(&store).args(["object", "list"]));
    assert!(out.contains("db/prod-password"));

    // Explain what the policy requires
    let out = assert_ok(tpm(&store).args(["policy", "explain", "boot-seal"]));
    assert!(out.contains("PCR"));
    assert!(out.contains("7"));
    assert!(out.contains("11"));

    // Test the policy
    let out = assert_ok(tpm(&store).args(["policy", "test", "boot-seal"]));
    assert!(out.contains("satisfiable"));
}

// ─── Workflow 3: Remote attestation ─────────────────────────────

#[test]
fn workflow_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("attest.db");
    let quote_file = dir.path().join("quote.json");

    assert_ok(tpm(&store).arg("init"));

    // Create attestation key
    let out = assert_ok(tpm(&store).args(["attest", "ak-create", "attest/node"]));
    assert!(out.contains("attestation key created"));

    // Save a PCR baseline
    assert_ok(tpm(&store).args(["pcr", "baseline", "save", "pre-attest", "--index", "0,7,11"]));

    // Generate a quote with a nonce
    let out = assert_ok(
        tpm(&store)
            .args([
                "attest",
                "quote",
                "--ak",
                "attest/node",
                "--pcr",
                "0,7,11",
                "--nonce",
                "verifier-challenge-abc",
                "--output",
            ])
            .arg(&quote_file),
    );
    assert!(out.contains("quote generated"));
    assert!(quote_file.exists());

    // The quote file should be valid JSON
    let quote_json = std::fs::read_to_string(&quote_file).unwrap();
    let quote: serde_json::Value = serde_json::from_str(&quote_json).unwrap();
    assert!(quote["pcr_values"].is_array());
    assert!(quote["nonce"].is_array());
    assert!(quote["signature"].is_array());

    // Verify the quote
    let out = assert_ok(
        tpm(&store)
            .args(["attest", "verify", "--quote"])
            .arg(&quote_file)
            .args(["--nonce", "verifier-challenge-abc"]),
    );
    assert!(out.contains("VERIFIED"));

    // Verify with wrong nonce fails verification
    let out = assert_ok(
        tpm(&store)
            .args(["attest", "verify", "--quote"])
            .arg(&quote_file)
            .args(["--nonce", "wrong-nonce"]),
    );
    assert!(out.contains("FAILED") || out.contains("MISMATCH"));

    // Check PCR baseline diff
    let out = assert_ok(tpm(&store).args(["pcr", "baseline", "diff", "pre-attest"]));
    assert!(out.contains("match"));
}

// ─── Workflow 4: NV storage for build metadata ──────────────────

#[test]
fn workflow_nv_build_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("nv.db");
    let data_file = dir.path().join("build.txt");
    let output_file = dir.path().join("read.txt");

    assert_ok(tpm(&store).arg("init"));

    // Define NV indices
    assert_ok(tpm(&store).args(["nv", "define", "config/build-id", "--size", "128"]));
    assert_ok(tpm(&store).args(["nv", "define", "config/commit-sha", "--size", "64"]));

    // List NV indices
    let out = assert_ok(tpm(&store).args(["nv", "list"]));
    assert!(out.contains("config/build-id"));
    assert!(out.contains("config/commit-sha"));

    // Write build ID
    std::fs::write(&data_file, "build-2026-03-28-001").unwrap();
    assert_ok(
        tpm(&store)
            .args(["nv", "write", "config/build-id", "--input"])
            .arg(&data_file),
    );

    // Read it back
    let out = assert_ok(tpm(&store).args(["nv", "read", "config/build-id"]));
    assert!(out.contains("build-2026-03-28-001"));

    // Read to file
    assert_ok(
        tpm(&store)
            .args(["nv", "read", "config/build-id", "--output"])
            .arg(&output_file),
    );
    let content = std::fs::read_to_string(&output_file).unwrap();
    assert_eq!(content, "build-2026-03-28-001");

    // Delete an index
    assert_ok(tpm(&store).args(["nv", "delete", "config/commit-sha"]));
    let out = assert_ok(tpm(&store).args(["nv", "list"]));
    assert!(!out.contains("config/commit-sha"));
    assert!(out.contains("config/build-id"));
}

// ─── Workflow 5: Policy YAML compilation ────────────────────────

#[test]
fn workflow_policy_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("policy.db");
    let policy_file = dir.path().join("boot.yaml");

    assert_ok(tpm(&store).arg("init"));

    // Write a YAML policy
    std::fs::write(
        &policy_file,
        r#"name: measured-boot
description: Requires boot integrity and auth
requires:
  pcr:
    - index: 0
    - index: 7
    - index: 11
  auth_value: true
"#,
    )
    .unwrap();

    // Compile it
    let out = assert_ok(tpm(&store).args(["policy", "compile"]).arg(&policy_file));
    assert!(out.contains("policy compiled: measured-boot"));
    assert!(out.contains("pcr sha256:0,7,11"));
    assert!(out.contains("password"));

    // Test it
    let out = assert_ok(tpm(&store).args(["policy", "test", "measured-boot"]));
    assert!(out.contains("all requirements satisfiable"));

    // Create a key with this policy
    let out = assert_ok(tpm(&store).args([
        "key",
        "create",
        "signing/boot-signed",
        "--policy",
        "measured-boot",
    ]));
    assert!(out.contains("key created"));

    // Verify the key shows the policy
    let out = assert_ok(tpm(&store).args(["key", "show", "signing/boot-signed"]));
    assert!(out.contains("measured-boot"));
}

// ─── Workflow 6: Workspace export/import ────────────────────────

#[test]
fn workflow_workspace_portability() {
    let dir = tempfile::tempdir().unwrap();
    let store1 = dir.path().join("source.db");
    let store2 = dir.path().join("target.db");
    let export_file = dir.path().join("workspace.json");

    // Set up source workspace
    assert_ok(tpm(&store1).arg("init"));
    assert_ok(tpm(&store1).args(["key", "create", "signing/app"]));
    assert_ok(tpm(&store1).args(["policy", "create", "boot", "--pcr", "7"]));

    // Export
    let out = assert_ok(
        tpm(&store1)
            .args(["workspace", "export", "--output"])
            .arg(&export_file),
    );
    assert!(out.contains("workspace exported"));

    // Verify export is valid JSON
    let json = std::fs::read_to_string(&export_file).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot["version"], 2);
    assert_eq!(snapshot["objects"].as_array().unwrap().len(), 1);

    // Import into new workspace
    assert_ok(tpm(&store2).arg("init"));
    let out = assert_ok(
        tpm(&store2)
            .args(["workspace", "import", "--input"])
            .arg(&export_file),
    );
    assert!(out.contains("workspace imported"));

    // Info on both
    let out = assert_ok(tpm(&store1).args(["workspace", "info"]));
    assert!(out.contains("objects:    1"));

    let out = assert_ok(tpm(&store2).args(["workspace", "info"]));
    assert!(out.contains("profiles:   1"));
}

// ─── Workflow 7: Repair after drift ─────────────────────────────

#[test]
fn workflow_repair() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("repair.db");

    assert_ok(tpm(&store).arg("init"));
    assert_ok(tpm(&store).args(["key", "create", "signing/a"]));
    assert_ok(tpm(&store).args(["key", "create", "signing/b"]));

    // Scan should show healthy
    let out = assert_ok(tpm(&store).args(["repair", "scan"]));
    assert!(out.contains("No issues found"));

    // Doctor should agree
    let out = assert_ok(tpm(&store).args(["doctor"]));
    assert!(out.contains("healthy"));

    // Status health
    let out = assert_ok(tpm(&store).args(["status"]));
    assert!(out.contains("Health:"));
    assert!(out.contains("100"));
}

// ─── Workflow 8: Full JSON output pipeline ──────────────────────

#[test]
fn workflow_json_everywhere() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("json.db");

    assert_ok(tpm(&store).arg("init"));
    assert_ok(tpm(&store).args(["key", "create", "signing/json"]));

    // Every command should produce valid JSON with --format json
    let commands: Vec<Vec<&str>> = vec![
        vec!["status", "--format", "json"],
        vec!["key", "list", "--format", "json"],
        vec!["key", "show", "signing/json", "--format", "json"],
        vec!["object", "list", "--format", "json"],
        vec!["object", "tree", "--format", "json"],
        vec!["profile", "list", "--format", "json"],
        vec!["policy", "list", "--format", "json"],
        vec!["log", "show", "--format", "json"],
        vec!["capabilities", "--format", "json"],
        vec!["doctor", "--format", "json"],
        vec!["repair", "scan", "--format", "json"],
        vec!["template", "list", "--format", "json"],
    ];

    for args in &commands {
        let out = assert_ok(tpm(&store).args(args));
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&out);
        assert!(
            parsed.is_ok(),
            "invalid JSON from `tpm {}`: {}",
            args.join(" "),
            out
        );
    }
}

// ─── Workflow 9: Object lifecycle (retire/activate/rename) ──────

#[test]
fn workflow_object_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("lifecycle.db");

    assert_ok(tpm(&store).arg("init"));
    assert_ok(tpm(&store).args(["key", "create", "signing/v1"]));

    // Rename
    let out = assert_ok(tpm(&store).args(["object", "rename", "signing/v1", "signing/old-v1"]));
    assert!(out.contains("renamed"));

    // Verify rename
    let out = assert_ok(tpm(&store).args(["key", "list"]));
    assert!(!out.contains("signing/v1\n")); // exact match gone
    assert!(out.contains("signing/old-v1"));

    // Retire
    let out = assert_ok(tpm(&store).args(["object", "retire", "signing/old-v1"]));
    assert!(out.contains("retired"));

    // Reactivate
    let out = assert_ok(tpm(&store).args(["object", "activate", "signing/old-v1"]));
    assert!(out.contains("activated"));

    // Delete
    let out = assert_ok(tpm(&store).args(["key", "delete", "signing/old-v1"]));
    assert!(out.contains("deleted"));

    // Verify empty
    let out = assert_ok(tpm(&store).args(["key", "list"]));
    assert!(out.contains("No keys found"));
}

// ─── Workflow 10: Error handling consistency ────────────────────

#[test]
fn workflow_error_handling() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("errors.db");

    assert_ok(tpm(&store).arg("init"));

    // Not found errors should include TPM error codes
    let err = assert_fail(tpm(&store).args(["key", "show", "nonexistent/key"]));
    assert!(err.contains("TPM0004") || err.contains("not found"));

    // Duplicate errors
    assert_ok(tpm(&store).args(["key", "create", "signing/dup"]));
    let err = assert_fail(tpm(&store).args(["key", "create", "signing/dup"]));
    assert!(err.contains("TPM0007") || err.contains("already exists"));

    // Invalid path
    let err = assert_fail(tpm(&store).args(["key", "show", "bad path!"]));
    assert!(err.contains("TPM0003") || err.contains("invalid"));

    // Policy not found
    let err =
        assert_fail(tpm(&store).args(["key", "create", "signing/x", "--policy", "no-such-policy"]));
    assert!(err.contains("not found"));

    // Plan mode produces no side effects
    let out = assert_ok(tpm(&store).args(["--plan", "key", "create", "signing/planned"]));
    assert!(out.contains("no changes made"));
    let err = assert_fail(tpm(&store).args(["key", "show", "signing/planned"]));
    assert!(err.contains("not found"));
}
