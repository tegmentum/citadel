use std::collections::HashMap;

use tpm_core::backend::TpmBackend;
use tpm_core::model::{
    Algorithm, Identity, IdentityUsage, ObjectKind, ObjectPath, Policy, PolicyRule, Profile,
    TpmObject,
};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::{Deserialize, Serialize};

// -- workspace export --

pub fn export(store: &Store, output: &std::path::Path, format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    let profiles = store.list_profiles()?;
    let nv_indices = store.list_nv_indices()?;
    let identities = store.list_identities()?;

    let snapshot = WorkspaceSnapshot {
        version: 2,
        objects: objects
            .iter()
            .map(|o| ExportedObject {
                id: o.id.to_string(),
                path: o.path.to_string(),
                kind: serde_json::to_value(o.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| format!("{:?}", o.kind)),
                algorithm: o.algorithm.to_string(),
                policy_id: o.policy_id.map(|id| id.to_string()),
                has_policy: o.policy_id.is_some(),
                created_at: o.created_at.to_rfc3339(),
                metadata: o.metadata.clone(),
            })
            .collect(),
        policies: policies
            .iter()
            .map(|p| ExportedPolicy {
                id: p.id.to_string(),
                name: p.name.clone(),
                rule_count: p.rules.len(),
                rules: p.rules.clone(),
            })
            .collect(),
        profiles: profiles
            .iter()
            .map(|p| ExportedProfile {
                name: p.name.clone(),
                default_algorithm: p.default_algorithm.to_string(),
                active: p.is_active,
            })
            .collect(),
        // Legacy string list of baseline names. The full baseline state
        // is not round-trippable today (values aren't re-exported);
        // kept as names for backwards compat with v1.
        pcr_baselines: store.list_pcr_baselines()?,
        nv_indices: nv_indices
            .iter()
            .map(|(name, idx, size)| ExportedNv {
                name: name.clone(),
                index: format!("0x{:08X}", idx),
                size: *size,
            })
            .collect(),
        identities: identities
            .iter()
            .map(|i| ExportedIdentity {
                id: i.id.to_string(),
                name: i.name.clone(),
                usage: i.usage.to_string(),
                key_object_id: i.key_object_id.to_string(),
                policy_id: i.policy_id.map(|id| id.to_string()),
                subject: i.subject.clone(),
                certificate_pem: i.certificate_pem.clone(),
                certificate_present: i.certificate_pem.is_some(),
                created_at: i.created_at.to_rfc3339(),
                rotated_from: i.rotated_from.map(|id| id.to_string()),
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&snapshot)?;
    std::fs::write(output, &json)?;

    let result = ExportResult {
        path: output.display().to_string(),
        objects: snapshot.objects.len(),
        policies: snapshot.policies.len(),
        profiles: snapshot.profiles.len(),
        identities: snapshot.identities.len(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

// -- workspace info --

pub fn info(
    store: &Store,
    store_path: &std::path::Path,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    let profiles = store.list_profiles()?;
    let active = store.get_active_profile()?;
    let baselines = store.list_pcr_baselines()?;
    let nv_indices = store.list_nv_indices()?;

    let result = WorkspaceInfo {
        store_path: store_path.display().to_string(),
        objects: objects.len(),
        policies: policies.len(),
        profiles: profiles.len(),
        active_profile: active.map(|p| p.name),
        pcr_baselines: baselines.len(),
        nv_indices: nv_indices.len(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

// -- Types --

#[derive(Serialize, Deserialize)]
struct WorkspaceSnapshot {
    version: u32,
    #[serde(default)]
    objects: Vec<ExportedObject>,
    #[serde(default)]
    policies: Vec<ExportedPolicy>,
    #[serde(default)]
    profiles: Vec<ExportedProfile>,
    #[serde(default)]
    pcr_baselines: Vec<String>,
    #[serde(default)]
    nv_indices: Vec<ExportedNv>,
    /// Identities (v2+)
    #[serde(default)]
    identities: Vec<ExportedIdentity>,
}

#[derive(Serialize, Deserialize)]
struct ExportedIdentity {
    /// Stable identity UUID (v2+).
    #[serde(default)]
    id: String,
    name: String,
    usage: String,
    key_object_id: String,
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    /// Full cert PEM, when present (v2+).
    #[serde(default)]
    certificate_pem: Option<String>,
    /// Legacy bool for display (v1). v2 also populates this for compat.
    #[serde(default)]
    certificate_present: bool,
    created_at: String,
    #[serde(default)]
    rotated_from: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ExportedObject {
    /// Stable object UUID (v2+). Absent on v1 snapshots.
    #[serde(default)]
    id: String,
    path: String,
    kind: String,
    algorithm: String,
    /// Policy UUID if attached (v2+).
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    has_policy: bool,
    created_at: String,
    /// Object metadata JSON (v2+).
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct ExportedPolicy {
    /// Stable policy UUID (v2+).
    #[serde(default)]
    id: String,
    name: String,
    rule_count: usize,
    /// Full rule set (v2+).
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

#[derive(Serialize, Deserialize)]
struct ExportedProfile {
    name: String,
    default_algorithm: String,
    active: bool,
}

#[derive(Serialize, Deserialize)]
struct ExportedNv {
    name: String,
    index: String,
    size: usize,
}

#[derive(Serialize)]
struct ExportResult {
    path: String,
    objects: usize,
    policies: usize,
    profiles: usize,
    identities: usize,
}

impl TextRenderable for ExportResult {
    fn render_text(&self) -> String {
        format!(
            "workspace exported to: {}\n  objects:    {}\n  policies:   {}\n  profiles:   {}\n  identities: {}\n",
            self.path, self.objects, self.policies, self.profiles, self.identities
        )
    }
}

#[derive(Serialize)]
struct WorkspaceInfo {
    store_path: String,
    objects: usize,
    policies: usize,
    profiles: usize,
    active_profile: Option<String>,
    pcr_baselines: usize,
    nv_indices: usize,
}

impl TextRenderable for WorkspaceInfo {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("store:      {}\n", self.store_path));
        out.push_str(&format!("objects:    {}\n", self.objects));
        out.push_str(&format!("policies:   {}\n", self.policies));
        out.push_str(&format!("profiles:   {}\n", self.profiles));
        out.push_str(&format!(
            "active:     {}\n",
            self.active_profile.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!("baselines:  {}\n", self.pcr_baselines));
        out.push_str(&format!("NV indices: {}\n", self.nv_indices));
        out
    }
}

// -- workspace import --

/// Import a workspace snapshot into the given store.
///
/// For v2 snapshots this materializes policies (with full rules), keys
/// (generating fresh TPM-side handle blobs via `backend.create_key`),
/// NV index definitions, and identities. Identity → key references are
/// preserved by inserting objects with their original UUIDs.
///
/// Conflicts (resource name already present) are skipped and surfaced
/// as warnings — the import is idempotent.
pub fn import(
    store: &Store,
    backend: &dyn TpmBackend,
    input: &std::path::Path,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(input)?;
    let snapshot: WorkspaceSnapshot = serde_json::from_str(&json)?;

    if snapshot.version != 1 && snapshot.version != 2 {
        anyhow::bail!(
            "[TPM0803] unsupported workspace snapshot version: {} (expected 1 or 2)",
            snapshot.version
        );
    }

    let mut report = ImportReport {
        source: input.display().to_string(),
        version: snapshot.version,
        ..Default::default()
    };

    // --- Profiles ---
    let existing_profiles = store.list_profiles()?;
    for ep in &snapshot.profiles {
        if existing_profiles.iter().any(|p| p.name == ep.name) {
            report.warnings.push(format!(
                "[TPM0804] profile '{}' already exists; skipped",
                ep.name
            ));
            continue;
        }
        let alg: Algorithm = ep.default_algorithm.parse().unwrap_or(Algorithm::EccP256);
        let profile = Profile {
            name: ep.name.clone(),
            default_algorithm: alg,
            default_policy: None,
            is_active: ep.active && existing_profiles.is_empty() && report.profiles_imported == 0,
            constraints: Default::default(),
        };
        store.insert_profile(&profile)?;
        report.profiles_imported += 1;
    }

    // --- Policies (v2 only carries rules; v1 just records the name) ---
    for ep in &snapshot.policies {
        if store.get_policy(&ep.name)?.is_some() {
            report.warnings.push(format!(
                "[TPM0804] policy '{}' already exists; skipped",
                ep.name
            ));
            continue;
        }
        if snapshot.version < 2 {
            // v1 had no rules; we can only warn.
            report.warnings.push(format!(
                "policy '{}' present in v1 snapshot without rules; skipped",
                ep.name
            ));
            continue;
        }
        let id = ep.id.parse().unwrap_or_else(|_| uuid::Uuid::new_v4());
        let policy = Policy {
            id,
            name: ep.name.clone(),
            rules: ep.rules.clone(),
        };
        store.insert_policy(&policy)?;
        report.policies_imported += 1;
    }

    // --- Objects (keys only — secrets need content we don't have) ---
    //
    // Track old_key_id → new path so identities can re-point. For v2
    // we preserve the original UUID verbatim; the map is just a sanity
    // check that the referenced key exists after insert.
    let mut imported_key_ids: HashMap<String, ObjectPath> = HashMap::new();

    for eo in &snapshot.objects {
        // Only handle keys; secrets need their actual content, which
        // we deliberately don't export.
        let kind = parse_object_kind(&eo.kind);
        let is_key = matches!(
            kind,
            Some(ObjectKind::SigningKey)
                | Some(ObjectKind::StorageKey)
                | Some(ObjectKind::AttestationKey)
        );
        if !is_key {
            continue;
        }

        let path = match ObjectPath::new(&eo.path) {
            Ok(p) => p,
            Err(e) => {
                report
                    .warnings
                    .push(format!("invalid object path '{}': {}", eo.path, e));
                continue;
            }
        };

        if store.get_object(&path)?.is_some() {
            report.warnings.push(format!(
                "[TPM0804] key '{}' already exists; skipped",
                eo.path
            ));
            continue;
        }

        let algorithm: Algorithm = match eo.algorithm.parse() {
            Ok(a) => a,
            Err(e) => {
                report
                    .warnings
                    .push(format!("key '{}' has invalid algorithm: {}", eo.path, e));
                continue;
            }
        };

        // Generate fresh backend handle material for this path.
        let handle = backend.create_key(algorithm, &path)?;

        // Preserve the original object UUID so identities (which may
        // reference it) continue to resolve. Falls back to a fresh
        // UUID for v1 snapshots.
        let id = eo
            .id
            .parse::<uuid::Uuid>()
            .unwrap_or_else(|_| uuid::Uuid::new_v4());

        // Re-point policy_id: v2 preserves the policy UUID across the
        // round-trip because we inserted policies with their original
        // IDs above.
        let policy_id = eo
            .policy_id
            .as_ref()
            .and_then(|s| s.parse::<uuid::Uuid>().ok());

        let obj = TpmObject {
            id,
            path: path.clone(),
            kind: kind.unwrap_or(ObjectKind::SigningKey),
            algorithm,
            policy_id,
            handle_blob: Some(handle.id),
            created_at: chrono::Utc::now(),
            metadata: eo.metadata.clone(),
        };
        store.insert_object(&obj)?;
        store.log_action(
            "workspace.import.key",
            Some(&eo.path),
            &serde_json::json!({"source": report.source, "algorithm": eo.algorithm}),
        )?;
        imported_key_ids.insert(eo.id.clone(), path);
        report.keys_imported += 1;
    }

    // --- NV indices (definition only; data is not re-exported) ---
    for en in &snapshot.nv_indices {
        if store.get_nv_index(&en.name)?.is_some() {
            report.warnings.push(format!(
                "[TPM0804] NV index '{}' already exists; skipped",
                en.name
            ));
            continue;
        }
        let idx_parsed = en
            .index
            .strip_prefix("0x")
            .or_else(|| en.index.strip_prefix("0X"))
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .or_else(|| en.index.parse::<u32>().ok());
        let Some(idx) = idx_parsed else {
            report.warnings.push(format!(
                "NV '{}' has unparseable index '{}'",
                en.name, en.index
            ));
            continue;
        };
        store.insert_nv_index(&en.name, idx, en.size)?;
        report.nv_imported += 1;
    }

    // --- Identities (last: depend on keys and policies) ---
    for ei in &snapshot.identities {
        if store.get_identity(&ei.name)?.is_some() {
            report.warnings.push(format!(
                "[TPM0804] identity '{}' already exists; skipped",
                ei.name
            ));
            continue;
        }
        if snapshot.version < 2 {
            report.warnings.push(format!(
                "identity '{}' in v1 snapshot cannot be restored (no stored UUIDs)",
                ei.name
            ));
            continue;
        }

        let key_object_id: uuid::Uuid = match ei.key_object_id.parse() {
            Ok(u) => u,
            Err(_) => {
                report.warnings.push(format!(
                    "identity '{}' has unparseable key_object_id",
                    ei.name
                ));
                continue;
            }
        };

        if store.get_object_by_id(&key_object_id)?.is_none() {
            report.warnings.push(format!(
                "identity '{}' references missing key {}; skipped",
                ei.name, key_object_id
            ));
            continue;
        }

        let usage: IdentityUsage = match ei.usage.parse() {
            Ok(u) => u,
            Err(e) => {
                report
                    .warnings
                    .push(format!("identity '{}' has invalid usage: {}", ei.name, e));
                continue;
            }
        };

        let id = ei
            .id
            .parse::<uuid::Uuid>()
            .unwrap_or_else(|_| uuid::Uuid::new_v4());
        let policy_id = ei
            .policy_id
            .as_ref()
            .and_then(|s| s.parse::<uuid::Uuid>().ok());

        let identity = Identity {
            id,
            name: ei.name.clone(),
            key_object_id,
            policy_id,
            usage,
            subject: ei.subject.clone(),
            certificate_pem: ei.certificate_pem.clone(),
            created_at: chrono::Utc::now(),
            rotated_from: ei
                .rotated_from
                .as_ref()
                .and_then(|s| s.parse::<uuid::Uuid>().ok()),
        };
        store.insert_identity(&identity)?;
        report.identities_imported += 1;
    }

    store.log_action(
        "workspace.import",
        None,
        &serde_json::json!({
            "source": report.source,
            "version": snapshot.version,
            "profiles_imported": report.profiles_imported,
            "policies_imported": report.policies_imported,
            "keys_imported": report.keys_imported,
            "nv_imported": report.nv_imported,
            "identities_imported": report.identities_imported,
            "warnings": report.warnings.len(),
        }),
    )?;

    println!("{}", render(&report, format));
    Ok(())
}

#[derive(Default, Serialize)]
struct ImportReport {
    source: String,
    version: u32,
    profiles_imported: usize,
    policies_imported: usize,
    keys_imported: usize,
    nv_imported: usize,
    identities_imported: usize,
    warnings: Vec<String>,
}

impl TextRenderable for ImportReport {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("workspace imported from: {}\n", self.source));
        out.push_str(&format!("  snapshot version: {}\n", self.version));
        out.push_str(&format!("  profiles:   {}\n", self.profiles_imported));
        out.push_str(&format!("  policies:   {}\n", self.policies_imported));
        out.push_str(&format!("  keys:       {}\n", self.keys_imported));
        out.push_str(&format!("  nv indices: {}\n", self.nv_imported));
        out.push_str(&format!("  identities: {}\n", self.identities_imported));
        if !self.warnings.is_empty() {
            out.push_str(&format!("\n  warnings ({}):\n", self.warnings.len()));
            for w in &self.warnings {
                out.push_str(&format!("    - {}\n", w));
            }
        }
        out
    }
}

/// Parse an `ObjectKind` from the string form stored in the snapshot.
/// Accepts both the Debug variant form (`"SigningKey"`) used by v1 and
/// the serde form (`"signing-key"`) used by v2.
fn parse_object_kind(s: &str) -> Option<ObjectKind> {
    // Try serde form first (kebab-case)
    if let Ok(k) = serde_json::from_value::<ObjectKind>(serde_json::json!(s)) {
        return Some(k);
    }
    // Fall back to Debug form
    match s {
        "SigningKey" => Some(ObjectKind::SigningKey),
        "StorageKey" => Some(ObjectKind::StorageKey),
        "AttestationKey" => Some(ObjectKind::AttestationKey),
        "SealedBlob" => Some(ObjectKind::SealedBlob),
        "NvIndex" => Some(ObjectKind::NvIndex),
        _ => None,
    }
}
