//! Workspace reconciler.
//!
//! Compares desired state (a Manifest) against the live store and
//! produces a plan of actions. Applies that plan when requested.

use chrono::Utc;
use uuid::Uuid;

use crate::backend::TpmBackend;
use crate::model::{Algorithm, Identity, IdentityUsage, Policy, Profile};
use crate::policy::manifest::{Manifest, ManifestKey, ManifestSecret};
use crate::service::keys::{create_key, CreateKeySpec};
use crate::service::plan::{PlannedAction, Risk};
use crate::store::Store;

/// Result of applying a manifest to a store.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplyReport {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub correlation_id: String,
}

/// Compute the diff between a manifest and the current store state.
///
/// Returns a list of PlannedActions representing what `apply` would do.
pub fn diff(store: &Store, manifest: &Manifest) -> anyhow::Result<Vec<PlannedAction>> {
    let mut actions = Vec::new();

    // Profile: always upsert
    if let Some(ref mp) = manifest.spec.profile {
        let existing = store
            .list_profiles()?
            .into_iter()
            .find(|p| p.name == mp.name);
        match existing {
            None => actions.push(PlannedAction {
                action: "create profile".to_string(),
                target: Some(mp.name.clone()),
                details: vec![("algorithm".to_string(), mp.default_algorithm.to_string())],
                risk: Risk::Low,
                reversible: true,
            }),
            Some(p) => {
                if p.default_algorithm != mp.default_algorithm {
                    actions.push(PlannedAction {
                        action: "update profile".to_string(),
                        target: Some(mp.name.clone()),
                        details: vec![(
                            "algorithm".to_string(),
                            format!("{} -> {}", p.default_algorithm, mp.default_algorithm),
                        )],
                        risk: Risk::Low,
                        reversible: true,
                    });
                }
            }
        }
    }

    // Policies: create missing; update on rule change
    for mp in &manifest.spec.policies {
        let existing = store.get_policy(&mp.name)?;
        let desired_rules = mp.compile();
        match existing {
            None => actions.push(PlannedAction {
                action: "create policy".to_string(),
                target: Some(mp.name.clone()),
                details: vec![("rules".to_string(), desired_rules.len().to_string())],
                risk: Risk::Low,
                reversible: true,
            }),
            Some(p) => {
                if p.rules != desired_rules {
                    actions.push(PlannedAction {
                        action: "update policy".to_string(),
                        target: Some(mp.name.clone()),
                        details: vec![(
                            "rules".to_string(),
                            format!("{} -> {}", p.rules.len(), desired_rules.len()),
                        )],
                        risk: Risk::Medium,
                        reversible: false,
                    });
                }
            }
        }
    }

    // Keys: create missing; warn on algorithm drift (force only in apply)
    for mk in &manifest.spec.keys {
        let path = crate::model::ObjectPath::new(&mk.path)
            .map_err(|e| anyhow::anyhow!("invalid key path '{}': {}", mk.path, e))?;
        let existing = store.get_object(&path)?;
        let desired_alg: Algorithm = mk
            .algorithm
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        match existing {
            None => actions.push(PlannedAction {
                action: "create key".to_string(),
                target: Some(mk.path.clone()),
                details: vec![
                    ("algorithm".to_string(), mk.algorithm.clone()),
                    (
                        "policy".to_string(),
                        mk.policy.clone().unwrap_or_else(|| "(none)".to_string()),
                    ),
                ],
                risk: Risk::Low,
                reversible: true,
            }),
            Some(obj) => {
                if obj.algorithm != desired_alg {
                    actions.push(PlannedAction {
                        action: "key algorithm drift (warn only; use --force to rotate)"
                            .to_string(),
                        target: Some(mk.path.clone()),
                        details: vec![(
                            "algorithm".to_string(),
                            format!("{} -> {}", obj.algorithm, desired_alg),
                        )],
                        risk: Risk::High,
                        reversible: false,
                    });
                }
            }
        }
    }

    // Secrets: create missing (Phase 3 doesn't track content drift)
    for ms in &manifest.spec.secrets {
        let path = crate::model::ObjectPath::new(&ms.name)
            .map_err(|e| anyhow::anyhow!("invalid secret name '{}': {}", ms.name, e))?;
        if store.get_object(&path)?.is_none() {
            actions.push(PlannedAction {
                action: "create secret (declared but not sealed)".to_string(),
                target: Some(ms.name.clone()),
                details: vec![(
                    "policy".to_string(),
                    ms.policy.clone().unwrap_or_else(|| "(none)".to_string()),
                )],
                risk: Risk::Low,
                reversible: true,
            });
        }
    }

    // Identities: create missing; flag drift on usage or key mismatch
    for mi in &manifest.spec.identities {
        let existing = store.get_identity(&mi.name)?;
        match existing {
            None => actions.push(PlannedAction {
                action: "create identity".to_string(),
                target: Some(mi.name.clone()),
                details: vec![
                    ("usage".to_string(), mi.usage.clone()),
                    ("key".to_string(), mi.key.clone()),
                ],
                risk: Risk::Low,
                reversible: true,
            }),
            Some(ident) => {
                let desired_usage: IdentityUsage =
                    mi.usage.parse().map_err(|e: String| anyhow::anyhow!(e))?;
                if ident.usage != desired_usage {
                    actions.push(PlannedAction {
                        action: "update identity usage".to_string(),
                        target: Some(mi.name.clone()),
                        details: vec![(
                            "usage".to_string(),
                            format!("{} -> {}", ident.usage, desired_usage),
                        )],
                        risk: Risk::Medium,
                        reversible: true,
                    });
                }
            }
        }
    }

    Ok(actions)
}

/// Apply a manifest to the store/backend.
///
/// Executes the actions from `diff`. With `force=true`, also rotates keys
/// on algorithm drift. Writes audit entries with the given correlation_id.
pub fn apply(
    store: &Store,
    backend: &dyn TpmBackend,
    manifest: &Manifest,
    force: bool,
) -> anyhow::Result<ApplyReport> {
    let correlation_id = Uuid::new_v4().to_string();
    let mut report = ApplyReport {
        correlation_id: correlation_id.clone(),
        ..Default::default()
    };

    // Profile upsert
    if let Some(ref mp) = manifest.spec.profile {
        let existing = store
            .list_profiles()?
            .into_iter()
            .find(|p| p.name == mp.name);
        let profile = Profile {
            name: mp.name.clone(),
            default_algorithm: mp.default_algorithm,
            default_policy: mp.default_policy.clone(),
            is_active: existing.as_ref().map(|p| p.is_active).unwrap_or(false),
            constraints: mp.constraints.clone(),
        };
        if existing.is_none() {
            store.insert_profile(&profile)?;
            report.created.push(format!("profile:{}", mp.name));
        } else {
            // For Phase 3, we can't update a profile in place; warn
            report
                .warnings
                .push(format!("profile '{}' already exists; no-op", mp.name));
        }
    }

    // Policies
    for mp in &manifest.spec.policies {
        let desired_rules = mp.compile();
        let existing = store.get_policy(&mp.name)?;
        match existing {
            None => {
                let policy = Policy {
                    id: Uuid::new_v4(),
                    name: mp.name.clone(),
                    rules: desired_rules,
                };
                store.insert_policy(&policy)?;
                store.log_action_with_correlation(
                    "manifest.policy.create",
                    None,
                    &serde_json::json!({"name": mp.name}),
                    &correlation_id,
                )?;
                report.created.push(format!("policy:{}", mp.name));
            }
            Some(existing) => {
                if existing.rules != desired_rules {
                    // Update: delete + insert (rules are immutable via store API)
                    store.delete_policy(&mp.name)?;
                    let policy = Policy {
                        id: Uuid::new_v4(),
                        name: mp.name.clone(),
                        rules: desired_rules,
                    };
                    store.insert_policy(&policy)?;
                    store.log_action_with_correlation(
                        "manifest.policy.update",
                        None,
                        &serde_json::json!({"name": mp.name}),
                        &correlation_id,
                    )?;
                    report.updated.push(format!("policy:{}", mp.name));
                }
            }
        }
    }

    // Keys
    for mk in &manifest.spec.keys {
        let path = crate::model::ObjectPath::new(&mk.path)
            .map_err(|e| anyhow::anyhow!("invalid key path '{}': {}", mk.path, e))?;
        let existing = store.get_object(&path)?;
        let desired_alg: Algorithm = mk
            .algorithm
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        match existing {
            None => {
                create_key(
                    store,
                    backend,
                    CreateKeySpec {
                        path: &mk.path,
                        algorithm: &mk.algorithm,
                        policy_name: mk.policy.as_deref(),
                    },
                )?;
                store.log_action_with_correlation(
                    "manifest.key.create",
                    Some(&mk.path),
                    &serde_json::json!({"algorithm": mk.algorithm}),
                    &correlation_id,
                )?;
                report.created.push(format!("key:{}", mk.path));
            }
            Some(obj) => {
                if obj.algorithm != desired_alg {
                    if force {
                        // Rotate: delete + create
                        store.delete_object(&path)?;
                        create_key(
                            store,
                            backend,
                            CreateKeySpec {
                                path: &mk.path,
                                algorithm: &mk.algorithm,
                                policy_name: mk.policy.as_deref(),
                            },
                        )?;
                        store.log_action_with_correlation(
                            "manifest.key.rotate",
                            Some(&mk.path),
                            &serde_json::json!({
                                "from_alg": obj.algorithm.to_string(),
                                "to_alg": desired_alg.to_string(),
                            }),
                            &correlation_id,
                        )?;
                        report.updated.push(format!("key:{} (rotated)", mk.path));
                    } else {
                        report.warnings.push(format!(
                            "key '{}' has algorithm drift ({} -> {}); use --force to rotate",
                            mk.path, obj.algorithm, desired_alg
                        ));
                    }
                }
            }
        }
    }

    // Secrets (Phase 3: create as placeholder objects)
    for ms in &manifest.spec.secrets {
        let path = crate::model::ObjectPath::new(&ms.name)
            .map_err(|e| anyhow::anyhow!("invalid secret name '{}': {}", ms.name, e))?;
        if store.get_object(&path)?.is_none() {
            // Declared but no content — leave as warning for user to seal manually
            report.warnings.push(format!(
                "secret '{}' declared in manifest but not sealed (run `tpm secret seal {} --input <file>`)",
                ms.name, ms.name
            ));
        }
    }

    // Identities: look up backing key object by path and insert
    for mi in &manifest.spec.identities {
        let existing = store.get_identity(&mi.name)?;
        let desired_usage: IdentityUsage =
            mi.usage.parse().map_err(|e: String| anyhow::anyhow!(e))?;

        match existing {
            None => {
                let key_path = crate::model::ObjectPath::new(&mi.key).map_err(|e| {
                    anyhow::anyhow!("invalid identity key path '{}': {}", mi.key, e)
                })?;
                let key_obj = store.get_object(&key_path)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "identity '{}' references undefined key '{}'",
                        mi.name,
                        mi.key
                    )
                })?;
                let policy_id = if let Some(pname) = &mi.policy {
                    store.get_policy(pname)?.map(|p| p.id)
                } else {
                    None
                };
                let identity = Identity {
                    id: Uuid::new_v4(),
                    name: mi.name.clone(),
                    key_object_id: key_obj.id,
                    policy_id,
                    usage: desired_usage,
                    subject: mi.subject.clone(),
                    certificate_pem: None,
                    created_at: Utc::now(),
                    rotated_from: None,
                };
                store.insert_identity(&identity)?;
                store.log_action_with_correlation(
                    "manifest.identity.create",
                    Some(&mi.name),
                    &serde_json::json!({
                        "usage": mi.usage,
                        "key": mi.key,
                    }),
                    &correlation_id,
                )?;
                report.created.push(format!("identity:{}", mi.name));
            }
            Some(ident) => {
                if ident.usage != desired_usage {
                    report.warnings.push(format!(
                        "identity '{}' usage drift ({} -> {}); manual update required",
                        mi.name, ident.usage, desired_usage
                    ));
                }
            }
        }
    }

    Ok(report)
}

// Silence unused warnings on ManifestKey/ManifestSecret imports in a way
// that keeps the module structure simple.
#[allow(dead_code)]
fn _type_anchor(_: &ManifestKey, _: &ManifestSecret) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::policy::Manifest;

    fn empty_store() -> Store {
        Store::memory()
    }

    #[test]
    fn diff_empty_manifest_is_noop() {
        let store = empty_store();
        let m = Manifest::from_yaml("apiVersion: tpm/v1\nkind: Workspace\nspec: {}\n").unwrap();
        let actions = diff(&store, &m).unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn diff_new_policy_and_key() {
        let store = empty_store();
        let yaml = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies:
    - name: boot
      requires:
        pcr:
          - index: 7
  keys:
    - path: signing/release
      algorithm: ecc-p256
      policy: boot
"#;
        let m = Manifest::from_yaml(yaml).unwrap();
        let actions = diff(&store, &m).unwrap();
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().any(|a| a.action.contains("create policy")));
        assert!(actions.iter().any(|a| a.action.contains("create key")));
    }

    #[test]
    fn apply_is_idempotent() {
        let store = empty_store();
        let backend = MockBackend::new();
        let yaml = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  policies:
    - name: boot
      requires:
        pcr:
          - index: 7
  keys:
    - path: signing/release
      algorithm: ecc-p256
      policy: boot
"#;
        let m = Manifest::from_yaml(yaml).unwrap();

        let report = apply(&store, &backend, &m, false).unwrap();
        assert_eq!(report.created.len(), 2);
        assert_eq!(report.updated.len(), 0);

        // Apply again: no changes
        let report2 = apply(&store, &backend, &m, false).unwrap();
        assert_eq!(report2.created.len(), 0);
        assert_eq!(report2.updated.len(), 0);

        // Diff should be empty after apply
        let actions = diff(&store, &m).unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn algorithm_drift_warns_without_force() {
        let store = empty_store();
        let backend = MockBackend::new();

        // Create with ecc-p256
        let yaml_v1 = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  keys:
    - path: signing/r
      algorithm: ecc-p256
"#;
        apply(
            &store,
            &backend,
            &Manifest::from_yaml(yaml_v1).unwrap(),
            false,
        )
        .unwrap();

        // Now try to change to rsa2048 without force
        let yaml_v2 = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  keys:
    - path: signing/r
      algorithm: rsa2048
"#;
        let m2 = Manifest::from_yaml(yaml_v2).unwrap();
        let report = apply(&store, &backend, &m2, false).unwrap();
        assert!(report.warnings.iter().any(|w| w.contains("drift")));

        // Key should still be ecc-p256
        let path = crate::model::ObjectPath::new("signing/r").unwrap();
        let obj = store.get_object(&path).unwrap().unwrap();
        assert_eq!(obj.algorithm, Algorithm::EccP256);
    }

    #[test]
    fn algorithm_drift_rotates_with_force() {
        let store = empty_store();
        let backend = MockBackend::new();

        let yaml_v1 = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  keys:
    - path: signing/r
      algorithm: ecc-p256
"#;
        apply(
            &store,
            &backend,
            &Manifest::from_yaml(yaml_v1).unwrap(),
            false,
        )
        .unwrap();

        let yaml_v2 = r#"
apiVersion: tpm/v1
kind: Workspace
spec:
  keys:
    - path: signing/r
      algorithm: rsa2048
"#;
        let m2 = Manifest::from_yaml(yaml_v2).unwrap();
        let report = apply(&store, &backend, &m2, true).unwrap();
        assert!(report.updated.iter().any(|u| u.contains("rotated")));

        let path = crate::model::ObjectPath::new("signing/r").unwrap();
        let obj = store.get_object(&path).unwrap().unwrap();
        assert_eq!(obj.algorithm, Algorithm::Rsa2048);
    }
}
