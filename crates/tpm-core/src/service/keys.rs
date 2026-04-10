//! Key orchestration services.
//!
//! Extracted from src/commands/key.rs so reconciler, identity service,
//! and daemon can all share the same creation logic.

use chrono::Utc;
use uuid::Uuid;

use crate::backend::TpmBackend;
use crate::diag::TpmError;
use crate::model::{Algorithm, ObjectKind, ObjectPath, TpmObject};
use crate::store::Store;

/// Specification for creating a key resource.
#[derive(Debug, Clone)]
pub struct CreateKeySpec<'a> {
    pub path: &'a str,
    pub algorithm: &'a str,
    pub policy_name: Option<&'a str>,
}

/// Create a signing key in the store and backend.
///
/// Returns the created TpmObject. Caller is responsible for rendering
/// the result and handling plan-mode.
pub fn create_key(
    store: &Store,
    backend: &dyn TpmBackend,
    spec: CreateKeySpec<'_>,
) -> anyhow::Result<TpmObject> {
    let path = ObjectPath::new(spec.path)
        .map_err(|e| TpmError::invalid_path(spec.path, &e.to_string()))?;

    if store.get_object(&path)?.is_some() {
        return Err(TpmError::object_already_exists(spec.path).into());
    }

    let algorithm: Algorithm = spec
        .algorithm
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let policy_id = if let Some(pname) = spec.policy_name {
        let policy = store
            .get_policy(pname)?
            .ok_or_else(|| TpmError::policy_not_found(pname))?;
        Some(policy.id)
    } else {
        None
    };

    let handle = backend.create_key(algorithm, &path)?;

    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm,
        policy_id,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };

    store.insert_object(&obj)?;
    store.log_action(
        "key.create",
        Some(path.as_str()),
        &serde_json::json!({"algorithm": algorithm.to_string()}),
    )?;

    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;

    #[test]
    fn creates_new_key() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let spec = CreateKeySpec {
            path: "signing/svc",
            algorithm: "ecc-p256",
            policy_name: None,
        };
        let obj = create_key(&store, &backend, spec).unwrap();
        assert_eq!(obj.path.as_str(), "signing/svc");
        assert_eq!(obj.algorithm, Algorithm::EccP256);
        assert!(obj.handle_blob.is_some());
    }

    #[test]
    fn rejects_duplicate() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let spec = CreateKeySpec {
            path: "signing/dup",
            algorithm: "ecc-p256",
            policy_name: None,
        };
        create_key(&store, &backend, spec.clone()).unwrap();
        let err = create_key(&store, &backend, spec).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn rejects_missing_policy() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let spec = CreateKeySpec {
            path: "signing/with-pol",
            algorithm: "ecc-p256",
            policy_name: Some("nonexistent"),
        };
        let err = create_key(&store, &backend, spec).unwrap_err();
        assert!(err.to_string().contains("policy not found"));
    }
}
