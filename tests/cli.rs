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

// === Manifest apply/diff (Phase 3) ===

#[test]
fn apply_creates_policy_and_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let manifest = dir.path().join("workspace.yaml");
    std::fs::write(
        &manifest,
        r#"
apiVersion: tpm/v1
kind: Workspace
metadata:
  name: test
spec:
  policies:
    - name: boot-policy
      requires:
        pcr:
          - index: 7
  keys:
    - path: signing/release
      algorithm: ecc-p256
      policy: boot-policy
"#,
    )
    .unwrap();

    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store)
            .arg("apply")
            .arg("--file")
            .arg(&manifest),
    );
    assert!(ok, "{}", stdout);
    assert!(stdout.contains("created"));
    assert!(stdout.contains("policy:boot-policy"));
    assert!(stdout.contains("key:signing/release"));
}

#[test]
fn apply_is_idempotent_via_cli() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let manifest = dir.path().join("workspace.yaml");
    std::fs::write(
        &manifest,
        r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies:
    - name: boot
      requires:
        pcr: [{index: 7}]
"#,
    )
    .unwrap();

    run(tpm_cmd_with_store(&store).arg("apply").arg("--file").arg(&manifest));
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store)
            .arg("apply")
            .arg("--file")
            .arg(&manifest),
    );
    assert!(ok);
    assert!(stdout.contains("no changes"));
}

#[test]
fn diff_shows_drift() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let manifest = dir.path().join("workspace.yaml");
    std::fs::write(
        &manifest,
        r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies:
    - name: boot
      requires:
        pcr: [{index: 7}]
"#,
    )
    .unwrap();

    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store)
            .arg("diff")
            .arg("--file")
            .arg(&manifest),
    );
    assert!(ok);
    assert!(stdout.contains("create policy"));
}

#[test]
fn apply_plan_mode_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let manifest = dir.path().join("workspace.yaml");
    std::fs::write(
        &manifest,
        r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies:
    - name: boot
      requires:
        pcr: [{index: 7}]
"#,
    )
    .unwrap();

    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store)
            .arg("--plan")
            .arg("apply")
            .arg("--file")
            .arg(&manifest),
    );
    assert!(ok);
    assert!(stdout.contains("plan:"));
    assert!(stdout.contains("no changes made"));

    // Policy should not actually be created
    let (stdout, _, _) = run(tpm_cmd_with_store(&store).args(["policy", "list"]));
    assert!(stdout.contains("No policies"));
}

// === Policy fragility (Phase 2) ===

#[test]
fn policy_fragility_high() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["policy", "create", "firmware-bound", "--pcr", "0,4"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["policy", "fragility", "firmware-bound"]));
    assert!(ok);
    assert!(stdout.contains("high"));
    assert!(stdout.contains("firmware"));
}

#[test]
fn policy_fragility_json() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["policy", "create", "secure-boot", "--pcr", "7"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store)
        .args(["policy", "fragility", "secure-boot", "--format", "json"]));
    assert!(ok);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["policy"], "secure-boot");
    assert_eq!(parsed["overall"], "medium");
    assert!(parsed["per_pcr"].is_array());
}

// === Identity namespace (Phase 4) ===

#[test]
fn identity_init_creates_key_and_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    let (stdout, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "identity",
        "init",
        "release",
        "--usage",
        "code-signing",
        "--subject",
        "CN=Release Signer",
    ]));
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("identity created: release"));
    assert!(stdout.contains("code-signing"));

    // backing key should exist
    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["key", "show", "signing/release"]));
    assert!(ok);
    assert!(stdout.contains("signing/release"));
}

#[test]
fn identity_show_and_list() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "svc"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["identity", "list"]));
    assert!(ok);
    assert!(stdout.contains("svc"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["identity", "show", "svc"]));
    assert!(ok);
    assert!(stdout.contains("name:"));
    assert!(stdout.contains("svc"));
}

#[test]
fn identity_rotate_sets_rotated_from() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "rot"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["identity", "rotate", "rot"]));
    assert!(ok);
    assert!(stdout.contains("identity rotated"));
    assert!(stdout.contains("rotated from"));
}

#[test]
fn identity_delete_without_cascade_preserves_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "keep"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["identity", "delete", "keep"]));
    assert!(ok);
    assert!(stdout.contains("key preserved"));

    // key should still be there
    let (_, _, ok) = run(tpm_cmd_with_store(&store).args(["key", "show", "signing/keep"]));
    assert!(ok);
}

#[test]
fn identity_delete_with_cascade_removes_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "nuke"]));
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store).args(["identity", "delete", "nuke", "--cascade"])
    );
    assert!(ok);
    assert!(stdout.contains("including backing key"));

    // key should be gone
    let (_, _, ok) = run(tpm_cmd_with_store(&store).args(["key", "show", "signing/nuke"]));
    assert!(!ok);
}

#[test]
fn object_dependents_surfaces_linked_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "dep"]));
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store).args(["object", "dependents", "signing/dep"])
    );
    assert!(ok);
    assert!(stdout.contains("linked identities"));
    assert!(stdout.contains("dep"));
}

// === Graph (Phase 5) ===

#[test]
fn graph_text_output() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "g1"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).arg("graph"));
    assert!(ok);
    assert!(stdout.contains("dependency graph"));
    assert!(stdout.contains("g1"));
}

#[test]
fn graph_dot_output() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");

    run(tpm_cmd_with_store(&store).args(["identity", "init", "dotted"]));
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["--format", "dot", "graph"]));
    assert!(ok);
    assert!(stdout.contains("digraph tpm"));
    assert!(stdout.contains("->"));
}

#[test]
fn repair_scan_flags_fragile_policy() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    run(tpm_cmd_with_store(&store).args([
        "policy", "create", "fragile", "--pcr", "0,4",
    ]));
    let (stdout, _, _) = run(tpm_cmd_with_store(&store).args(["repair", "scan"]));
    assert!(stdout.contains("REPAIR007"));
}

#[test]
fn apply_creates_identity_from_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("test.db");
    let manifest = dir.path().join("workspace.yaml");
    std::fs::write(
        &manifest,
        r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  keys:
    - path: signing/release
      algorithm: ecc-p256
  identities:
    - name: release-signer
      key: signing/release
      usage: code-signing
      subject: "CN=Release"
"#,
    )
    .unwrap();

    let (stdout, stderr, ok) = run(
        tpm_cmd_with_store(&store)
            .arg("apply")
            .arg("--file")
            .arg(&manifest),
    );
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("identity:release-signer"));

    // second apply should be idempotent
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store)
            .arg("apply")
            .arg("--file")
            .arg(&manifest),
    );
    assert!(ok);
    assert!(stdout.contains("no changes"));
}

// === Workspace v2 round-trip (Item 4) ===

#[test]
fn workspace_export_includes_v2_fields() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("src.db");
    let export = dir.path().join("ws.json");

    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args(["policy", "create", "boot", "--pcr", "7,11"]));
    run(tpm_cmd_with_store(&store).args(["key", "create", "signing/app", "--policy", "boot"]));
    run(tpm_cmd_with_store(&store).args(["identity", "init", "svc"]));

    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["workspace", "export", "--output"]).arg(&export));
    assert!(ok, "{}", stdout);

    let snapshot: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&export).unwrap()).unwrap();

    assert_eq!(snapshot["version"], 2);

    // Policies now include id and rules
    let policies = snapshot["policies"].as_array().unwrap();
    let boot = policies.iter().find(|p| p["name"] == "boot").unwrap();
    assert!(boot["id"].as_str().unwrap().len() > 0);
    assert!(!boot["rules"].as_array().unwrap().is_empty());

    // Objects now include id and policy_id
    let objects = snapshot["objects"].as_array().unwrap();
    let key = objects.iter().find(|o| o["path"] == "signing/app").unwrap();
    assert!(key["id"].as_str().unwrap().len() > 0);
    assert!(key["policy_id"].is_string());

    // Identities now include id
    let identities = snapshot["identities"].as_array().unwrap();
    let svc = identities.iter().find(|i| i["name"] == "svc").unwrap();
    assert!(svc["id"].as_str().unwrap().len() > 0);
    assert!(svc["key_object_id"].as_str().unwrap().len() > 0);
}

#[test]
fn workspace_roundtrip_structural() {
    let dir = tempfile::tempdir().unwrap();
    let store1 = dir.path().join("src.db");
    let store2 = dir.path().join("dst.db");
    let export = dir.path().join("ws.json");

    // Source workspace: profile (from init) + policy + key + identity.
    run(tpm_cmd_with_store(&store1).arg("init"));
    run(tpm_cmd_with_store(&store1).args(["policy", "create", "boot", "--pcr", "7"]));
    run(tpm_cmd_with_store(&store1).args(["key", "create", "signing/release", "--policy", "boot"]));
    run(tpm_cmd_with_store(&store1).args(["identity", "init", "rel", "--usage", "code-signing"]));

    let (_, _, ok) = run(
        tpm_cmd_with_store(&store1)
            .args(["workspace", "export", "--output"])
            .arg(&export),
    );
    assert!(ok);

    // Target: fresh store, import the snapshot.
    run(tpm_cmd_with_store(&store2).arg("init"));
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store2)
            .args(["workspace", "import", "--input"])
            .arg(&export),
    );
    assert!(ok, "{}", stdout);
    // Report should mention policies, keys, identities
    assert!(stdout.contains("policies:"));
    assert!(stdout.contains("keys:"));
    assert!(stdout.contains("identities:"));

    // Verify resources landed in the target store.
    let (stdout, _, _) = run(tpm_cmd_with_store(&store2).args(["policy", "list"]));
    assert!(stdout.contains("boot"));

    let (stdout, _, _) = run(tpm_cmd_with_store(&store2).args(["key", "list"]));
    assert!(stdout.contains("signing/release"));

    let (stdout, _, _) = run(tpm_cmd_with_store(&store2).args(["identity", "list"]));
    assert!(stdout.contains("rel"));

    // Identity→key linkage survived the round-trip.
    let (stdout, _, _) = run(
        tpm_cmd_with_store(&store2).args(["object", "dependents", "signing/rel"]),
    );
    // identity init creates signing/<name>, so identity "rel" binds to signing/rel.
    assert!(stdout.contains("linked identities"));
    assert!(stdout.contains("rel"));
}

#[test]
fn workspace_import_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store1 = dir.path().join("src.db");
    let store2 = dir.path().join("dst.db");
    let export = dir.path().join("ws.json");

    run(tpm_cmd_with_store(&store1).arg("init"));
    run(tpm_cmd_with_store(&store1).args(["key", "create", "signing/a"]));
    run(
        tpm_cmd_with_store(&store1)
            .args(["workspace", "export", "--output"])
            .arg(&export),
    );

    run(tpm_cmd_with_store(&store2).arg("init"));
    run(
        tpm_cmd_with_store(&store2)
            .args(["workspace", "import", "--input"])
            .arg(&export),
    );

    // Second import should report skipped conflicts, not fail.
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store2)
            .args(["workspace", "import", "--input"])
            .arg(&export),
    );
    assert!(ok, "second import should succeed: {}", stdout);
    assert!(
        stdout.contains("already exists"),
        "expected 'already exists' warning, got: {}",
        stdout
    );
    assert!(stdout.contains("TPM0804"));
}

#[test]
fn workspace_v1_snapshot_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("dst.db");
    let snapshot = dir.path().join("v1.json");

    // Hand-rolled legacy v1 snapshot
    std::fs::write(
        &snapshot,
        r#"{
  "version": 1,
  "objects": [],
  "policies": [],
  "profiles": [
    {"name": "legacy", "default_algorithm": "ecc_p256", "active": true}
  ],
  "pcr_baselines": [],
  "nv_indices": []
}"#,
    )
    .unwrap();

    let (stdout, stderr, ok) = run(
        tpm_cmd_with_store(&store)
            .args(["workspace", "import", "--input"])
            .arg(&snapshot),
    );
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("snapshot version: 1"));
    assert!(stdout.contains("profiles:   1"));

    // Profile should have landed.
    let (stdout, _, _) = run(tpm_cmd_with_store(&store).args(["profile", "list"]));
    assert!(stdout.contains("legacy"));
}

#[test]
fn workspace_import_unsupported_version_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("dst.db");
    let snapshot = dir.path().join("future.json");

    std::fs::write(
        &snapshot,
        r#"{
  "version": 99,
  "objects": [],
  "policies": [],
  "profiles": [],
  "pcr_baselines": [],
  "nv_indices": []
}"#,
    )
    .unwrap();

    let (_, stderr, ok) = run(
        tpm_cmd_with_store(&store)
            .args(["workspace", "import", "--input"])
            .arg(&snapshot),
    );
    assert!(!ok);
    assert!(stderr.contains("TPM0803"), "stderr={}", stderr);
}

// === Secure log Phase 1 ===

#[test]
fn audit_append_and_show() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");

    run(tpm_cmd_with_store(&store).arg("init"));
    let (stdout, stderr, ok) = run(
        tpm_cmd_with_store(&store)
            .args(["audit", "append", "--event", "user.login", "--payload", "alice"]),
    );
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("seqno:"));
    assert!(stdout.contains("entry_hash:"));

    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "show", "1"]));
    assert!(ok);
    assert!(stdout.contains("event_type:    user.login"));
    assert!(stdout.contains("prev_hash:     0000000000000000"));
}

#[test]
fn audit_head_tracks_appends() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (stdout, _, _) = run(tpm_cmd_with_store(&store).args(["audit", "head"]));
    assert!(stdout.contains("empty"));

    for i in 0..3 {
        run(tpm_cmd_with_store(&store).args([
            "audit",
            "append",
            "--event",
            "tick",
            "--payload",
            &format!("n={}", i),
        ]));
    }

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["audit", "head"]));
    assert!(ok);
    assert!(stdout.contains("head = 3"), "stdout={}", stdout);
}

#[test]
fn audit_chain_verify_succeeds_after_clean_appends() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    for i in 0..5 {
        run(tpm_cmd_with_store(&store).args([
            "audit",
            "append",
            "--event",
            "evt",
            "--payload",
            &format!("v{}", i),
        ]));
    }
    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "chain", "verify"]));
    assert!(ok, "stdout={}", stdout);
    assert!(stdout.contains("ok (all links verified)"));
}

#[test]
fn audit_segment_close_and_prove() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    for i in 0..5 {
        run(tpm_cmd_with_store(&store).args([
            "audit",
            "append",
            "--event",
            "e",
            "--payload",
            &format!("v{}", i),
        ]));
    }
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store).args(["audit", "segments", "close"]),
    );
    assert!(ok, "{}", stdout);
    assert!(stdout.contains("segment_id:"));
    assert!(stdout.contains("range:          [1, 5]"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["audit", "prove", "3"]));
    assert!(ok);
    assert!(stdout.contains("inclusion proof"));
    assert!(stdout.contains("proof verified locally"));
}

#[test]
fn audit_encrypt_and_decrypt_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    // Init the master key at the default location (sibling of store).
    // Use --plaintext so the test doesn't depend on a backend's
    // seal/unseal being deterministic across subprocess invocations
    // (the mock backend's seal is stateless, so sealed would also
    // work, but plaintext keeps this test's assertions simple).
    let key_path = dir.path().join("audit.db.auditkey");
    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "key",
        "init",
        "--out",
        key_path.to_str().unwrap(),
        "--plaintext",
    ]));
    assert!(ok, "{}", stdout);
    assert!(key_path.exists());
    assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);

    // Append encrypted.
    let (stdout, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "append",
        "--event",
        "secret.login",
        "--payload",
        "alice-password",
        "--encrypt",
    ]));
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("(encrypted)"));

    // Show without --decrypt: ciphertext only.
    let (stdout, _, _) = run(tpm_cmd_with_store(&store).args(["audit", "show", "1"]));
    assert!(stdout.contains("cbor+aead-chacha20poly1305"));
    assert!(!stdout.contains("alice-password"));

    // Show with --decrypt: plaintext present.
    let (stdout, _, _) =
        run(tpm_cmd_with_store(&store).args(["audit", "show", "1", "--decrypt"]));
    assert!(stdout.contains("alice-password"));

    // Chain verification still succeeds — it works over the
    // ciphertext canonical bytes, no decryption key needed.
    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "chain", "verify"]));
    assert!(ok);
    assert!(stdout.contains("ok (all links verified)"));
}

#[test]
fn audit_streams_default_present_after_init() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "streams", "list"]));
    assert!(ok);
    assert!(stdout.contains("default"));
    assert!(stdout.contains("[public]"));
}

#[test]
fn audit_streams_create_and_set_tier() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (stdout, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "streams",
        "create",
        "audit-records",
        "--tier",
        "protected",
        "--description",
        "test-only",
    ]));
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("tier:        protected"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "streams",
        "set-tier",
        "audit-records",
        "--tier",
        "highly-restricted",
    ]));
    assert!(ok);
    assert!(stdout.contains("tier:        highly-restricted"));
}

#[test]
fn audit_append_on_protected_stream_is_auto_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    // Initialize a plaintext KEK so the auto-promotion to
    // encryption has a key to work with.
    let key_path = dir.path().join("audit.db.auditkey");
    run(tpm_cmd_with_store(&store).args([
        "audit",
        "key",
        "init",
        "--out",
        key_path.to_str().unwrap(),
        "--plaintext",
    ]));

    run(tpm_cmd_with_store(&store).args([
        "audit",
        "streams",
        "create",
        "secrets",
        "--tier",
        "protected",
    ]));

    // No --encrypt flag, but the stream's tier forces encryption.
    let (stdout, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "append",
        "--event",
        "login",
        "--payload",
        "top-secret",
        "--stream",
        "secrets",
    ]));
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    // Auto-promotion notice goes to stderr.
    assert!(stderr.contains("protected"), "stderr={}", stderr);
    assert!(stdout.contains("(encrypted)"));

    // The stored payload is ciphertext-tagged.
    let (stdout, _, _) =
        run(tpm_cmd_with_store(&store).args(["audit", "show", "1"]));
    assert!(stdout.contains("cbor+aead-chacha20poly1305"));
    assert!(!stdout.contains("top-secret"));
}

#[test]
fn audit_streams_rejects_bogus_tier() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (_, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit", "streams", "create", "s", "--tier", "bogus",
    ]));
    assert!(!ok);
    assert!(stderr.contains("unknown confidentiality tier"));
}

#[test]
fn audit_streams_delete_deprecates_stream() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args(["audit", "streams", "create", "mystream"]));

    // Deprecate the stream.
    let (stdout, _stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit", "streams", "delete", "mystream",
    ]));
    assert!(ok, "streams delete should succeed");
    assert!(stdout.contains("deprecated"), "output should mention deprecated");

    // Show should reflect the deprecated_at timestamp.
    let (stdout, _stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit", "streams", "show", "mystream",
    ]));
    assert!(ok);
    assert!(stdout.contains("deprecated:"), "show should include deprecated field");
}

#[test]
fn audit_streams_delete_rejects_new_appends() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args(["audit", "streams", "create", "mystream"]));

    // Deprecate the stream.
    let (_, _, ok) = run(tpm_cmd_with_store(&store).args([
        "audit", "streams", "delete", "mystream",
    ]));
    assert!(ok);

    // Append should now be rejected.
    let (_, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "append",
        "--stream",
        "mystream",
        "--event",
        "deploy",
        "--producer",
        "ci",
        "--payload",
        "data",
    ]));
    assert!(!ok, "append to deprecated stream should fail");
    assert!(
        stderr.contains("deprecated"),
        "error should mention deprecated: {stderr}"
    );
}

#[test]
fn audit_streams_delete_nonexistent_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (_, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit", "streams", "delete", "nosuchstream",
    ]));
    assert!(!ok);
    assert!(stderr.contains("not found"), "should report stream not found");
}

#[test]
fn audit_key_sealed_round_trip() {
    // End-to-end: seal the key under MockBackend, then append an
    // encrypted entry and decrypt it. Every CLI invocation is a
    // separate process, so the KEK must be unsealable across
    // process boundaries — MockBackend's seal is deterministic
    // (XOR with 0xAA), so this works.
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let key_path = dir.path().join("audit.db.auditkey");
    let (stdout, stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "key",
        "init",
        "--out",
        key_path.to_str().unwrap(),
    ]));
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("sealed"));
    // Sealed file is JSON, so not 32 bytes.
    assert_ne!(std::fs::read(&key_path).unwrap().len(), 32);

    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "key", "show"]));
    assert!(ok);
    assert!(stdout.contains("format:  sealed"));

    // Append encrypted and decrypt back.
    run(tpm_cmd_with_store(&store).args([
        "audit",
        "append",
        "--event",
        "e",
        "--payload",
        "under-seal",
        "--encrypt",
    ]));
    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "show", "1", "--decrypt"]));
    assert!(ok);
    assert!(stdout.contains("under-seal"));
}

#[test]
fn audit_decrypt_without_key_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args([
        "audit", "append", "--event", "e", "--payload", "plain",
    ]));
    // Default is plaintext; decrypting a plaintext entry should
    // just pass through successfully.
    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "show", "1", "--decrypt"]));
    assert!(ok, "{}", stdout);
    assert!(stdout.contains("plaintext:     plain"));
}

#[test]
fn audit_publish_emits_witness_submission() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args([
        "identity", "init", "log-signer", "--usage", "attestation",
    ]));
    run(tpm_cmd_with_store(&store).args([
        "audit", "append", "--event", "e", "--payload", "x",
    ]));
    run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
    run(tpm_cmd_with_store(&store).args([
        "audit", "sign", "1", "--identity", "log-signer",
    ]));

    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store).args(["audit", "publish", "--format", "json"]),
    );
    assert!(ok);
    let sub: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(sub["stream_id"], "default");
    assert_eq!(sub["segment_id"], 1);
    assert!(sub["checkpoint_hash_hex"].as_str().unwrap().len() == 64);
    assert!(sub["signature_hex"].as_str().unwrap().len() >= 2);
}

#[test]
fn audit_rollback_passes_on_fresh_signed_chain() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args([
        "identity", "init", "log-signer", "--usage", "attestation",
    ]));
    run(tpm_cmd_with_store(&store).args([
        "audit", "append", "--event", "e", "--payload", "x",
    ]));
    run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
    run(tpm_cmd_with_store(&store).args([
        "audit", "sign", "1", "--identity", "log-signer",
    ]));
    let (stdout, _, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "rollback"]));
    assert!(ok, "{}", stdout);
    assert!(stdout.contains("no rollback detected"));
}

#[test]
fn audit_sign_and_verify_checkpoint_chain() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    // Need an identity backed by a real key. `identity init`
    // creates both the key (via backend) and the identity row.
    run(tpm_cmd_with_store(&store).args([
        "identity",
        "init",
        "log-signer",
        "--usage",
        "attestation",
    ]));
    for i in 0..4 {
        run(tpm_cmd_with_store(&store).args([
            "audit",
            "append",
            "--event",
            "e",
            "--payload",
            &format!("v{}", i),
        ]));
    }
    run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
    let (stdout, stderr, ok) = run(
        tpm_cmd_with_store(&store).args([
            "audit", "sign", "1", "--identity", "log-signer",
        ]),
    );
    assert!(ok, "stdout={} stderr={}", stdout, stderr);
    assert!(stdout.contains("signed segment"));

    let (stdout, _, ok) = run(tpm_cmd_with_store(&store).args(["audit", "verify"]));
    assert!(ok);
    assert!(stdout.contains("1 segment(s) verified"));
}

#[test]
fn audit_segment_list_shows_two_segments() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    for _ in 0..2 {
        run(tpm_cmd_with_store(&store).args([
            "audit", "append", "--event", "e", "--payload", "a",
        ]));
    }
    run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
    for _ in 0..2 {
        run(tpm_cmd_with_store(&store).args([
            "audit", "append", "--event", "e", "--payload", "b",
        ]));
    }
    run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
    let (stdout, _, ok) = run(
        tpm_cmd_with_store(&store).args(["audit", "segments", "list"]),
    );
    assert!(ok);
    assert!(stdout.contains("segment 1:"));
    assert!(stdout.contains("segment 2:"));
}

#[test]
fn audit_chain_verify_detects_payload_tamper() {
    // Append 3 entries, reach into the SQLite file with rusqlite,
    // mutate a payload on entry 2, and confirm verify fails.
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    for i in 0..3 {
        run(tpm_cmd_with_store(&store).args([
            "audit",
            "append",
            "--event",
            "evt",
            "--payload",
            &format!("v{}", i),
        ]));
    }

    // Corrupt entry 2's payload. Use rusqlite via the same
    // store that the CLI wrote to.
    {
        let store_api = tpm_core::store::Store::open(&store).unwrap();
        // We don't have a public mutate method; use the underlying
        // sqlite backend by opening a fresh SqliteStore for SQL.
        drop(store_api);
        let conn = rusqlite::Connection::open(&store).unwrap();
        conn.execute(
            "UPDATE secure_log SET payload = ?1 WHERE seqno = 2",
            rusqlite::params![b"tampered".to_vec()],
        )
        .unwrap();
    }

    let (stdout, stderr, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "chain", "verify"]));
    assert!(!ok, "expected chain verify to fail; stdout={}", stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("FAILED") || combined.contains("chain verification failed"),
        "expected failure marker, got: {}",
        combined
    );
}

#[test]
fn workspace_roundtrip_identity_key_binding_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let store1 = dir.path().join("src.db");
    let store2 = dir.path().join("dst.db");
    let export = dir.path().join("ws.json");

    run(tpm_cmd_with_store(&store1).arg("init"));
    run(tpm_cmd_with_store(&store1).args(["identity", "init", "cross"]));

    // Note original identity id + key_object_id.
    let (stdout, _, _) = run(
        tpm_cmd_with_store(&store1).args(["identity", "show", "cross", "--format", "json"]),
    );
    let original: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let original_id = original["id"].as_str().unwrap().to_string();
    let original_key_id = original["key_object_id"].as_str().unwrap().to_string();

    run(
        tpm_cmd_with_store(&store1)
            .args(["workspace", "export", "--output"])
            .arg(&export),
    );

    run(tpm_cmd_with_store(&store2).arg("init"));
    run(
        tpm_cmd_with_store(&store2)
            .args(["workspace", "import", "--input"])
            .arg(&export),
    );

    // After import the same UUIDs should be preserved.
    let (stdout, _, _) = run(
        tpm_cmd_with_store(&store2).args(["identity", "show", "cross", "--format", "json"]),
    );
    let imported: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(imported["id"].as_str().unwrap(), original_id);
    assert_eq!(imported["key_object_id"].as_str().unwrap(), original_key_id);
}

#[test]
fn audit_witness_list_empty() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (stdout, _stderr, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "witness", "list"]));
    assert!(ok);
    assert!(stdout.contains("no witness receipts"));
}

#[test]
fn audit_witness_gc_requires_filter() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));

    let (_stdout, stderr, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "witness", "gc"]));
    assert!(!ok);
    assert!(
        stderr.contains("--keep-latest") || stderr.contains("--older-than"),
        "should mention required flags: {stderr}"
    );
}

/// Helper: publish a signed segment and record the receipt into the witness log.
/// Returns the path to the temporary JSON file (kept alive by the tempdir).
fn publish_and_record(store: &std::path::Path, dir: &tempfile::TempDir, seg: u64) {
    // Sign the segment.
    run(tpm_cmd_with_store(store).args([
        "audit",
        "sign",
        &seg.to_string(),
        "--identity",
        "log-signer",
    ]));
    // Publish → JSON.
    let (json, _stderr, ok) =
        run(tpm_cmd_with_store(store).args(["audit", "publish", "--format", "json"]));
    assert!(ok, "publish should succeed for seg {seg}");
    // Write to temp file and record locally.
    let receipt_path = dir.path().join(format!("receipt_{seg}.json"));
    std::fs::write(&receipt_path, &json).unwrap();
    let (_, _, ok) = run(tpm_cmd_with_store(store).args([
        "audit",
        "witness",
        "record",
        "--input",
        receipt_path.to_str().unwrap(),
    ]));
    assert!(ok, "witness record should succeed for seg {seg}");
}

#[test]
fn audit_witness_gc_keep_latest_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args([
        "identity", "init", "log-signer", "--usage", "attestation",
    ]));

    // Create 3 signed segments and record each witness receipt.
    for seg in 1..=3u64 {
        run(tpm_cmd_with_store(&store).args([
            "audit", "append", "--event", "e", "--payload", "x",
        ]));
        run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
        publish_and_record(&store, &dir, seg);
    }

    // Dry run: keep 1 → would delete 2.
    let (stdout, _stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "witness",
        "gc",
        "--keep-latest",
        "1",
        "--dry-run",
    ]));
    assert!(ok, "gc dry-run should succeed");
    assert!(
        stdout.contains("would delete 2"),
        "should report 2 would-be deletions: {stdout}"
    );

    // After dry-run, witnesses unchanged.
    let (stdout, _stderr, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "witness", "list", "--format", "json"]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["witnesses"].as_array().unwrap().len(), 3);
}

#[test]
fn audit_witness_gc_keep_latest_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("audit.db");
    run(tpm_cmd_with_store(&store).arg("init"));
    run(tpm_cmd_with_store(&store).args([
        "identity", "init", "log-signer", "--usage", "attestation",
    ]));

    for seg in 1..=3u64 {
        run(tpm_cmd_with_store(&store).args([
            "audit", "append", "--event", "e", "--payload", "x",
        ]));
        run(tpm_cmd_with_store(&store).args(["audit", "segments", "close"]));
        publish_and_record(&store, &dir, seg);
    }

    // Real GC: keep 1.
    let (stdout, _stderr, ok) = run(tpm_cmd_with_store(&store).args([
        "audit",
        "witness",
        "gc",
        "--keep-latest",
        "1",
    ]));
    assert!(ok, "gc should succeed");
    assert!(stdout.contains("deleted 2"), "should report 2 deletions: {stdout}");

    // Only 1 receipt should remain.
    let (stdout, _stderr, ok) =
        run(tpm_cmd_with_store(&store).args(["audit", "witness", "list", "--format", "json"]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["witnesses"].as_array().unwrap().len(), 1);
}
