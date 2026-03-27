use tpm_core::backend::{MockBackend, TpmBackend};
use tpm_core::diag::{DiagCode, Diagnostic};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, Profile, TpmObject};
use tpm_core::output::format::{render, OutputFormat, TextRenderable};
use tpm_core::store::Store;

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

/// End-to-end smoke test: mock backend -> store -> output pipeline.
#[test]
fn full_pipeline_key_lifecycle() {
    // Set up store and backend
    let store = Store::open_memory().unwrap();
    let backend = MockBackend::new();

    // Verify backend status
    let status = backend.status().unwrap();
    assert!(status.available);
    assert_eq!(status.backend_type, "mock");

    // Set up a default profile
    let profile = Profile::builtin_default();
    store.insert_profile(&profile).unwrap();
    let active = store.get_active_profile().unwrap().unwrap();
    assert_eq!(active.name, "default");

    // Create a key via backend
    let path = ObjectPath::new("signing/release").unwrap();
    let handle = backend.create_key(Algorithm::EccP256, &path).unwrap();

    // Store the object
    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm: Algorithm::EccP256,
        policy_id: None,
        handle_blob: Some(handle.id.clone()),
        created_at: Utc::now(),
        metadata: serde_json::json!({"purpose": "release signing"}),
    };
    store.insert_object(&obj).unwrap();

    // Log the action
    store
        .log_action(
            "key.create",
            Some("signing/release"),
            &serde_json::json!({"algorithm": "ecc_p256"}),
        )
        .unwrap();

    // Retrieve it
    let fetched = store.get_object(&path).unwrap().unwrap();
    assert_eq!(fetched.path, path);
    assert_eq!(fetched.algorithm, Algorithm::EccP256);
    assert_eq!(fetched.kind, ObjectKind::SigningKey);

    // Sign some data
    let data = b"release artifact v1.0.0";
    let signature = backend.sign(&handle, data).unwrap();
    assert!(!signature.is_empty());

    // List objects
    let objects = store.list_objects().unwrap();
    assert_eq!(objects.len(), 1);

    // Test output formatting in all modes
    #[derive(Serialize)]
    struct Summary {
        path: String,
        algorithm: String,
    }

    impl TextRenderable for Summary {
        fn render_text(&self) -> String {
            format!("{} ({})", self.path, self.algorithm)
        }
    }

    let summary = Summary {
        path: "signing/release".to_string(),
        algorithm: "ecc-p256".to_string(),
    };

    let text = render(&summary, OutputFormat::Text);
    assert!(text.contains("signing/release"));

    let json = render(&summary, OutputFormat::Json);
    assert!(json.contains("\"path\""));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["path"], "signing/release");

    let yaml = render(&summary, OutputFormat::Yaml);
    assert!(yaml.contains("path:"));
}

#[test]
fn diagnostic_rendering() {
    let diag = Diagnostic::error(DiagCode::E0004, "object not found: signing/missing")
        .with_cause("no object with path 'signing/missing' in store")
        .with_suggestion("run `tpm key list` to see available keys")
        .with_context("path", "signing/missing")
        .with_context("store", "/tmp/test.db");

    let text = diag.render_text();
    assert!(text.contains("error[TPM0004]"));
    assert!(text.contains("object not found"));
    assert!(text.contains("signing/missing"));
    assert!(text.contains("tpm key list"));

    let json = diag.render_json();
    assert_eq!(json["code"], "TPM0004");
    assert_eq!(json["suggestions"][0], "run `tpm key list` to see available keys");
}

#[test]
fn duplicate_object_detection() {
    let store = Store::open_memory().unwrap();
    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: ObjectPath::new("signing/dup").unwrap(),
        kind: ObjectKind::SigningKey,
        algorithm: Algorithm::EccP256,
        policy_id: None,
        handle_blob: None,
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };
    store.insert_object(&obj).unwrap();

    // Inserting same path should fail (UNIQUE constraint)
    let obj2 = TpmObject {
        id: Uuid::new_v4(),
        path: ObjectPath::new("signing/dup").unwrap(),
        kind: ObjectKind::SigningKey,
        algorithm: Algorithm::Rsa2048,
        policy_id: None,
        handle_blob: None,
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };
    assert!(store.insert_object(&obj2).is_err());
}

#[test]
fn backend_list_handles() {
    let backend = MockBackend::new();
    let p1 = ObjectPath::new("key/a").unwrap();
    let p2 = ObjectPath::new("key/b").unwrap();

    backend.create_key(Algorithm::EccP256, &p1).unwrap();
    backend.create_key(Algorithm::Rsa2048, &p2).unwrap();

    let handles = backend.list_handles().unwrap();
    assert_eq!(handles.len(), 2);
}
