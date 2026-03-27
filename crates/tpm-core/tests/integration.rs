use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::{MockBackend, TpmBackend};
use tpm_core::diag::{DiagCode, Diagnostic, TpmError};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, Policy, PolicyRule, Profile, TpmObject};
use tpm_core::output::format::{render, OutputFormat, TextRenderable};
use tpm_core::policy::PolicyDefinition;
use tpm_core::store::Store;

fn setup() -> (Store, MockBackend) {
    let store = Store::open_memory().unwrap();
    let backend = MockBackend::new();
    (store, backend)
}

fn create_test_key(store: &Store, backend: &MockBackend, path: &str) -> TpmObject {
    let obj_path = ObjectPath::new(path).unwrap();
    let handle = backend.create_key(Algorithm::EccP256, &obj_path).unwrap();
    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: obj_path,
        kind: ObjectKind::SigningKey,
        algorithm: Algorithm::EccP256,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };
    store.insert_object(&obj).unwrap();
    obj
}

// === Key Lifecycle Tests ===

#[test]
fn key_create_sign_delete() {
    let (store, backend) = setup();
    let obj = create_test_key(&store, &backend, "signing/test");

    // Sign data
    let handle = tpm_core::backend::KeyHandle {
        id: obj.handle_blob.clone().unwrap(),
        path: "signing/test".to_string(),
    };
    let sig = backend.sign(&handle, b"hello world").unwrap();
    assert!(!sig.is_empty());

    // Deterministic: same input produces same signature
    let sig2 = backend.sign(&handle, b"hello world").unwrap();
    assert_eq!(sig, sig2);

    // Different input produces different signature
    let sig3 = backend.sign(&handle, b"different data").unwrap();
    assert_ne!(sig, sig3);

    // Delete
    let path = ObjectPath::new("signing/test").unwrap();
    assert!(store.delete_object(&path).unwrap());
    assert!(store.get_object(&path).unwrap().is_none());
}

#[test]
fn key_with_policy() {
    let (store, _backend) = setup();

    let policy = Policy {
        id: Uuid::new_v4(),
        name: "test-policy".to_string(),
        rules: vec![PolicyRule::PcrMatch {
            bank: "sha256".to_string(),
            indices: vec![7, 11],
        }],
    };
    store.insert_policy(&policy).unwrap();

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: ObjectPath::new("signing/with-policy").unwrap(),
        kind: ObjectKind::SigningKey,
        algorithm: Algorithm::EccP256,
        policy_id: Some(policy.id),
        handle_blob: None,
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };
    store.insert_object(&obj).unwrap();

    let fetched = store
        .get_object(&ObjectPath::new("signing/with-policy").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(fetched.policy_id, Some(policy.id));

    let fetched_policy = store.get_policy_by_id(&policy.id).unwrap().unwrap();
    assert_eq!(fetched_policy.name, "test-policy");
}

// === Secret Seal/Unseal Tests ===

#[test]
fn seal_unseal_roundtrip() {
    let (_store, backend) = setup();

    let plaintext = b"super secret database password";
    let sealed = backend.seal(plaintext, None).unwrap();
    assert_ne!(sealed.blob, plaintext.as_slice());

    let recovered = backend.unseal(&sealed).unwrap();
    assert_eq!(recovered, plaintext.as_slice());
}

#[test]
fn seal_with_policy_digest() {
    let (_store, backend) = setup();

    let policy_digest = vec![0xAB; 32];
    let sealed = backend
        .seal(b"secret", Some(&policy_digest))
        .unwrap();
    assert_eq!(sealed.policy_digest, Some(policy_digest));

    let recovered = backend.unseal(&sealed).unwrap();
    assert_eq!(recovered, b"secret");
}

// === NV Index Tests ===

#[test]
fn nv_lifecycle() {
    let (store, backend) = setup();

    backend.nv_define(0x01000001, 64).unwrap();
    store.insert_nv_index("config/test", 0x01000001, 64).unwrap();

    // Write via store
    store.nv_write_data("config/test", b"hello nv").unwrap();

    // Read back
    let data = store.nv_read_data("config/test").unwrap().unwrap();
    assert_eq!(data, b"hello nv");

    // List
    let indices = store.list_nv_indices().unwrap();
    assert_eq!(indices.len(), 1);
    assert_eq!(indices[0].0, "config/test");

    // Delete
    assert!(store.delete_nv_index("config/test").unwrap());
    assert!(store.get_nv_index("config/test").unwrap().is_none());
}

#[test]
fn nv_duplicate_index_rejected() {
    let (_store, backend) = setup();

    backend.nv_define(0x01000001, 64).unwrap();
    assert!(backend.nv_define(0x01000001, 64).is_err());
}

// === PCR and Attestation Tests ===

#[test]
fn pcr_read_deterministic() {
    let (_store, backend) = setup();

    let values1 = backend.pcr_read("sha256", &[0, 7, 11]).unwrap();
    let values2 = backend.pcr_read("sha256", &[0, 7, 11]).unwrap();

    assert_eq!(values1.len(), 3);
    for (a, b) in values1.iter().zip(values2.iter()) {
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.index, b.index);
    }
}

#[test]
fn pcr_values_unique_per_index() {
    let (_store, backend) = setup();

    let values = backend.pcr_read("sha256", &[0, 7]).unwrap();
    assert_ne!(values[0].digest, values[1].digest);
}

#[test]
fn attestation_quote_verify_roundtrip() {
    let (_store, backend) = setup();

    let ak = backend.create_ak(Algorithm::EccP256).unwrap();
    let nonce = b"challenge-12345";

    let quote = backend
        .quote(&ak, nonce, "sha256", &[0, 7, 11])
        .unwrap();

    assert_eq!(quote.nonce, nonce.as_slice());
    assert_eq!(quote.pcr_values.len(), 3);
    assert!(!quote.signature.is_empty());
    assert!(!quote.attestation.is_empty());

    let verification = backend
        .verify_quote(&quote, &quote.ak_public, nonce)
        .unwrap();

    assert!(verification.signature_valid);
    assert!(verification.nonce_matches);
    assert!(verification.verified);
    assert!(verification.pcr_matches.iter().all(|m| m.matches));
}

#[test]
fn attestation_wrong_nonce_fails() {
    let (_store, backend) = setup();

    let ak = backend.create_ak(Algorithm::EccP256).unwrap();
    let quote = backend
        .quote(&ak, b"correct-nonce", "sha256", &[0, 7])
        .unwrap();

    let verification = backend
        .verify_quote(&quote, &quote.ak_public, b"wrong-nonce")
        .unwrap();

    assert!(!verification.nonce_matches);
    assert!(!verification.verified);
}

// === PCR Baseline Tests ===

#[test]
fn pcr_baseline_save_and_diff() {
    let (store, backend) = setup();

    let values = backend.pcr_read("sha256", &[0, 7]).unwrap();
    let values_json = serde_json::json!(
        values
            .iter()
            .map(|v| serde_json::json!({
                "index": v.index,
                "digest": v.digest.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            }))
            .collect::<Vec<_>>()
    );

    store
        .save_pcr_baseline("test-baseline", "sha256", &values_json)
        .unwrap();

    let (bank, saved) = store.get_pcr_baseline("test-baseline").unwrap().unwrap();
    assert_eq!(bank, "sha256");
    assert!(saved.is_array());

    let baselines = store.list_pcr_baselines().unwrap();
    assert!(baselines.contains(&"test-baseline".to_string()));
}

// === Policy DSL Tests ===

#[test]
fn policy_dsl_compile_and_store() {
    let (store, _backend) = setup();

    let yaml = r#"
name: boot-and-auth
description: Requires boot state and password
requires:
  pcr:
    - index: 7
    - index: 11
  auth_value: true
"#;
    let def = PolicyDefinition::from_yaml(yaml).unwrap();
    assert_eq!(def.name, "boot-and-auth");
    assert!(def.description.is_some());

    let issues = def.validate();
    assert!(issues.is_empty(), "validation issues: {:?}", issues);

    let rules = def.compile();
    assert_eq!(rules.len(), 2);

    let policy = Policy {
        id: Uuid::new_v4(),
        name: def.name.clone(),
        rules,
    };
    store.insert_policy(&policy).unwrap();

    let fetched = store.get_policy("boot-and-auth").unwrap().unwrap();
    assert_eq!(fetched.rules.len(), 2);
}

#[test]
fn policy_dsl_validation_catches_errors() {
    let yaml = r#"
name: bad-policy
requires:
  pcr:
    - index: 50
      bank: sha999
"#;
    let def = PolicyDefinition::from_yaml(yaml).unwrap();
    let issues = def.validate();
    assert!(issues.len() >= 2);
    assert!(issues.iter().any(|i| i.message.contains("out of range")));
    assert!(issues.iter().any(|i| i.message.contains("unknown PCR bank")));
}

// === Profile Tests ===

#[test]
fn profile_switch() {
    let (store, _backend) = setup();

    store.insert_profile(&Profile::builtin_default()).unwrap();
    store
        .insert_profile(&Profile {
            name: "ci".to_string(),
            default_algorithm: Algorithm::Rsa2048,
            default_policy: None,
            is_active: false,
        })
        .unwrap();

    let active = store.get_active_profile().unwrap().unwrap();
    assert_eq!(active.name, "default");

    store.set_active_profile("ci").unwrap();
    let active = store.get_active_profile().unwrap().unwrap();
    assert_eq!(active.name, "ci");
    assert_eq!(active.default_algorithm, Algorithm::Rsa2048);
}

#[test]
fn profile_set_nonexistent_fails() {
    let (store, _backend) = setup();
    store.insert_profile(&Profile::builtin_default()).unwrap();
    assert!(store.set_active_profile("nonexistent").is_err());
}

// === Audit Log Tests ===

#[test]
fn audit_log_filtering() {
    let (store, _backend) = setup();

    store
        .log_action("key.create", Some("signing/a"), &serde_json::json!({}))
        .unwrap();
    store
        .log_action("key.create", Some("signing/b"), &serde_json::json!({}))
        .unwrap();
    store
        .log_action("policy.create", None, &serde_json::json!({}))
        .unwrap();
    store
        .log_action("key.sign", Some("signing/a"), &serde_json::json!({}))
        .unwrap();

    // Filter by action
    let key_entries = store.list_audit_log(None, Some("key"), 100).unwrap();
    assert_eq!(key_entries.len(), 3);

    // Filter by object
    let obj_entries = store
        .list_audit_log(Some("signing/a"), None, 100)
        .unwrap();
    assert_eq!(obj_entries.len(), 2);

    // Limit
    let limited = store.list_audit_log(None, None, 2).unwrap();
    assert_eq!(limited.len(), 2);
}

// === Diagnostic Tests ===

#[test]
fn tpm_error_convenience_constructors() {
    let err = TpmError::object_not_found("signing/missing");
    assert_eq!(err.diagnostic.code, DiagCode::E0004);
    assert!(err.diagnostic.message.contains("signing/missing"));
    assert!(!err.diagnostic.suggestions.is_empty());

    let err = TpmError::policy_not_found("boot-policy");
    assert_eq!(err.diagnostic.code, DiagCode::E0400);

    let err = TpmError::type_mismatch("obj", "signing key", "sealed blob");
    assert_eq!(err.diagnostic.code, DiagCode::E0100);
    assert!(err.diagnostic.message.contains("sealed blob"));
}

#[test]
fn diagnostic_render_all_formats() {
    let diag = Diagnostic::error(DiagCode::E0004, "test error")
        .with_cause("cause 1")
        .with_suggestion("fix it")
        .with_context("key", "value");

    let text = diag.render_text();
    assert!(text.contains("error[TPM0004]"));
    assert!(text.contains("cause 1"));
    assert!(text.contains("fix it"));

    let json = diag.render_json();
    assert_eq!(json["code"], "TPM0004");
    assert_eq!(json["causes"][0], "cause 1");
}

// === Output Format Tests ===

#[test]
fn output_format_all_modes() {
    #[derive(serde::Serialize)]
    struct TestData {
        name: String,
        count: u32,
    }

    impl TextRenderable for TestData {
        fn render_text(&self) -> String {
            format!("{}: {}", self.name, self.count)
        }
    }

    let data = TestData {
        name: "test".to_string(),
        count: 42,
    };

    let text = render(&data, OutputFormat::Text);
    assert_eq!(text, "test: 42");

    let json = render(&data, OutputFormat::Json);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["name"], "test");
    assert_eq!(parsed["count"], 42);

    let yaml = render(&data, OutputFormat::Yaml);
    assert!(yaml.contains("name: test"));
    assert!(yaml.contains("count: 42"));
}

// === Object Path Validation ===

#[test]
fn object_path_edge_cases() {
    // Single segment
    assert!(ObjectPath::new("key").is_ok());

    // Deep nesting
    assert!(ObjectPath::new("a/b/c/d/e").is_ok());

    // Hyphens and underscores
    assert!(ObjectPath::new("my-key_v2/sub-key").is_ok());

    // Numeric
    assert!(ObjectPath::new("key123/456").is_ok());

    // Dots rejected
    assert!(ObjectPath::new("key.old").is_err());

    // Unicode rejected
    assert!(ObjectPath::new("clé").is_err());
}

// === Store Migration Robustness ===

#[test]
fn store_migration_v2_creates_tables() {
    let store = Store::open_memory().unwrap();

    // v2 tables should exist after migration
    store.insert_nv_index("test", 0x01000001, 64).unwrap();
    store
        .save_pcr_baseline("test", "sha256", &serde_json::json!([]))
        .unwrap();

    let nv = store.list_nv_indices().unwrap();
    assert_eq!(nv.len(), 1);

    let baselines = store.list_pcr_baselines().unwrap();
    assert_eq!(baselines.len(), 1);
}
