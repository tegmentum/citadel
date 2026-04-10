//! Identity orchestration services.
//!
//! An identity is a composite resource: signing key + policy + intended
//! usage + cert metadata. These functions create, rotate, and delete
//! identities while keeping the underlying key objects in sync.

use chrono::Utc;
use uuid::Uuid;

use crate::backend::TpmBackend;
use crate::diag::TpmError;
use crate::model::{Identity, IdentityUsage, ObjectPath};
use crate::store::Store;

use super::keys::{create_key, CreateKeySpec};

/// Specification for creating a new identity.
#[derive(Debug, Clone)]
pub struct InitIdentitySpec<'a> {
    pub name: &'a str,
    pub usage: IdentityUsage,
    pub algorithm: &'a str,
    pub policy_name: Option<&'a str>,
    pub subject: Option<&'a str>,
    /// Override key path. Defaults to `signing/<name>` when None.
    pub key_path: Option<&'a str>,
}

/// Initialize a new identity: create its backing key, then record the identity.
pub fn init_identity(
    store: &Store,
    backend: &dyn TpmBackend,
    spec: InitIdentitySpec<'_>,
) -> anyhow::Result<Identity> {
    if store.get_identity(spec.name)?.is_some() {
        anyhow::bail!("identity already exists: {}", spec.name);
    }

    let key_path_owned = spec
        .key_path
        .map(String::from)
        .unwrap_or_else(|| format!("signing/{}", spec.name));

    let key = create_key(
        store,
        backend,
        CreateKeySpec {
            path: &key_path_owned,
            algorithm: spec.algorithm,
            policy_name: spec.policy_name,
        },
    )?;

    let policy_id = if let Some(pname) = spec.policy_name {
        store.get_policy(pname)?.map(|p| p.id)
    } else {
        None
    };

    let identity = Identity {
        id: Uuid::new_v4(),
        name: spec.name.to_string(),
        key_object_id: key.id,
        policy_id,
        usage: spec.usage,
        subject: spec.subject.map(String::from),
        certificate_pem: None,
        created_at: Utc::now(),
        rotated_from: None,
    };

    store.insert_identity(&identity)?;
    store.log_action(
        "identity.init",
        Some(spec.name),
        &serde_json::json!({
            "usage": identity.usage.as_str(),
            "key": key_path_owned,
            "algorithm": spec.algorithm,
        }),
    )?;

    Ok(identity)
}

/// Rotate an identity's underlying key.
///
/// Creates a new key (with a rotation suffix path), points the identity at it,
/// and records the old key id in `rotated_from`. The old key is preserved.
pub fn rotate_identity(
    store: &Store,
    backend: &dyn TpmBackend,
    name: &str,
) -> anyhow::Result<Identity> {
    let identity = store
        .get_identity(name)?
        .ok_or_else(|| TpmError::identity_not_found(name))?;

    let old_key = store
        .list_objects()?
        .into_iter()
        .find(|o| o.id == identity.key_object_id)
        .ok_or_else(|| {
            TpmError::identity_missing_key(name, &identity.key_object_id.to_string())
        })?;

    // Derive a new key path; append a timestamped rotation suffix.
    let ts = Utc::now().format("%Y%m%d%H%M%S");
    let rotated_path = format!("{}-rot{}", old_key.path.as_str(), ts);

    let new_key = create_key(
        store,
        backend,
        CreateKeySpec {
            path: &rotated_path,
            algorithm: &old_key.algorithm.to_string(),
            policy_name: None,
        },
    )
    .map_err(|e| anyhow::anyhow!("identity rotation failed: {}", e))?;

    store.update_identity_key(name, &new_key.id, &old_key.id)?;
    store.log_action(
        "identity.rotate",
        Some(name),
        &serde_json::json!({
            "old_key": old_key.path.as_str(),
            "new_key": rotated_path,
            "rotated_from": old_key.id.to_string(),
        }),
    )?;

    // Return the refreshed identity
    store
        .get_identity(name)?
        .ok_or_else(|| TpmError::identity_not_found(name).into())
}

/// Delete an identity.
///
/// If `cascade` is true, also delete the underlying key object.
/// Otherwise the key is preserved.
pub fn delete_identity(store: &Store, name: &str, cascade: bool) -> anyhow::Result<()> {
    let identity = store
        .get_identity(name)?
        .ok_or_else(|| TpmError::identity_not_found(name))?;

    let key_path = if cascade {
        store
            .list_objects()?
            .into_iter()
            .find(|o| o.id == identity.key_object_id)
            .map(|o| o.path)
    } else {
        None
    };

    if !store.delete_identity(name)? {
        anyhow::bail!("identity not found: {}", name);
    }

    if let Some(path) = key_path {
        store.delete_object(&path)?;
        store.log_action(
            "identity.delete",
            Some(name),
            &serde_json::json!({"cascade": true, "key": path.as_str()}),
        )?;
    } else {
        store.log_action(
            "identity.delete",
            Some(name),
            &serde_json::json!({"cascade": false}),
        )?;
    }

    Ok(())
}

/// Resolve the ObjectPath of the key backing an identity.
pub fn key_path_for_identity(store: &Store, identity: &Identity) -> anyhow::Result<ObjectPath> {
    store
        .list_objects()?
        .into_iter()
        .find(|o| o.id == identity.key_object_id)
        .map(|o| o.path)
        .ok_or_else(|| {
            TpmError::identity_missing_key(&identity.name, &identity.key_object_id.to_string())
                .into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;

    fn spec(name: &str) -> InitIdentitySpec<'_> {
        InitIdentitySpec {
            name,
            usage: IdentityUsage::CodeSigning,
            algorithm: "ecc-p256",
            policy_name: None,
            subject: Some("CN=Test"),
            key_path: None,
        }
    }

    #[test]
    fn init_creates_key_and_identity() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let ident = init_identity(&store, &backend, spec("release")).unwrap();
        assert_eq!(ident.name, "release");
        assert_eq!(ident.usage, IdentityUsage::CodeSigning);
        assert!(store.get_object(&ObjectPath::new("signing/release").unwrap()).unwrap().is_some());
        assert!(store.get_identity("release").unwrap().is_some());
    }

    #[test]
    fn init_rejects_duplicate() {
        let store = Store::memory();
        let backend = MockBackend::new();
        init_identity(&store, &backend, spec("dup")).unwrap();
        let err = init_identity(&store, &backend, spec("dup")).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn rotate_creates_new_key_and_records_predecessor() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let orig = init_identity(&store, &backend, spec("rot")).unwrap();
        let rotated = rotate_identity(&store, &backend, "rot").unwrap();
        assert_ne!(rotated.key_object_id, orig.key_object_id);
        assert_eq!(rotated.rotated_from, Some(orig.key_object_id));
    }

    #[test]
    fn delete_without_cascade_preserves_key() {
        let store = Store::memory();
        let backend = MockBackend::new();
        init_identity(&store, &backend, spec("keepkey")).unwrap();
        delete_identity(&store, "keepkey", false).unwrap();
        assert!(store.get_identity("keepkey").unwrap().is_none());
        assert!(store
            .get_object(&ObjectPath::new("signing/keepkey").unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn delete_with_cascade_removes_key() {
        let store = Store::memory();
        let backend = MockBackend::new();
        init_identity(&store, &backend, spec("nukekey")).unwrap();
        delete_identity(&store, "nukekey", true).unwrap();
        assert!(store.get_identity("nukekey").unwrap().is_none());
        assert!(store
            .get_object(&ObjectPath::new("signing/nukekey").unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_identity_by_key_surfaces_dependents() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let ident = init_identity(&store, &backend, spec("deps")).unwrap();
        let found = store.get_identity_by_key(&ident.key_object_id).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "deps");
    }
}
