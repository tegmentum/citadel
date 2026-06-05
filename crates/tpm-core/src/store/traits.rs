use crate::model::{Identity, ObjectPath, Policy, Profile, TpmObject};

/// An entry from the audit log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub object_path: Option<String>,
    pub details: String,
}

/// Abstract storage backend.
///
/// Implementations provide persistence for the TPM workspace metadata.
/// The SQLite backend is used natively; the memory backend is used for
/// WASM targets and tests.
pub trait StoreBackend: Send {
    // -- Objects --
    fn insert_object(&self, obj: &TpmObject) -> anyhow::Result<()>;
    fn get_object(&self, path: &ObjectPath) -> anyhow::Result<Option<TpmObject>>;
    fn get_object_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<TpmObject>>;
    fn list_objects(&self) -> anyhow::Result<Vec<TpmObject>>;
    fn delete_object(&self, path: &ObjectPath) -> anyhow::Result<bool>;
    fn rename_object(&self, old_path: &ObjectPath, new_path: &ObjectPath) -> anyhow::Result<()>;
    fn set_object_state(&self, path: &ObjectPath, state: &str) -> anyhow::Result<()>;
    fn touch_object(&self, path: &ObjectPath) -> anyhow::Result<()>;
    fn object_count(&self) -> anyhow::Result<usize>;

    // -- Profiles --
    fn insert_profile(&self, profile: &Profile) -> anyhow::Result<()>;
    fn get_active_profile(&self) -> anyhow::Result<Option<Profile>>;
    fn list_profiles(&self) -> anyhow::Result<Vec<Profile>>;
    fn set_active_profile(&self, name: &str) -> anyhow::Result<()>;

    // -- Policies --
    fn insert_policy(&self, policy: &Policy) -> anyhow::Result<()>;
    fn get_policy(&self, name: &str) -> anyhow::Result<Option<Policy>>;
    fn get_policy_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<Policy>>;
    fn list_policies(&self) -> anyhow::Result<Vec<Policy>>;
    fn delete_policy(&self, name: &str) -> anyhow::Result<bool>;

    // -- NV Indices --
    fn insert_nv_index(&self, name: &str, nv_index: u32, size: usize) -> anyhow::Result<()>;
    fn get_nv_index(&self, name: &str) -> anyhow::Result<Option<(u32, usize)>>;
    fn list_nv_indices(&self) -> anyhow::Result<Vec<(String, u32, usize)>>;
    fn nv_write_data(&self, name: &str, data: &[u8]) -> anyhow::Result<()>;
    fn nv_read_data(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>>;
    fn delete_nv_index(&self, name: &str) -> anyhow::Result<bool>;

    // -- PCR Baselines --
    fn save_pcr_baseline(
        &self,
        name: &str,
        bank: &str,
        values: &serde_json::Value,
    ) -> anyhow::Result<()>;
    fn get_pcr_baseline(&self, name: &str) -> anyhow::Result<Option<(String, serde_json::Value)>>;
    fn list_pcr_baselines(&self) -> anyhow::Result<Vec<String>>;

    // -- Audit --
    fn log_action(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
    ) -> anyhow::Result<()>;
    fn log_action_with_correlation(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
        correlation_id: &str,
    ) -> anyhow::Result<()>;
    fn list_audit_log(
        &self,
        filter_object: Option<&str>,
        filter_action: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEntry>>;

    // -- Approvals --
    fn insert_approval(&self, approval: &crate::model::ApprovalRequest) -> anyhow::Result<()>;
    fn get_approval(&self, id: &uuid::Uuid) -> anyhow::Result<Option<crate::model::ApprovalRequest>>;
    fn list_approvals(&self) -> anyhow::Result<Vec<crate::model::ApprovalRequest>>;
    fn update_approval_status(
        &self,
        id: &uuid::Uuid,
        status: crate::model::ApprovalStatus,
        resolved_by: Option<&str>,
    ) -> anyhow::Result<()>;

    // -- Identities --
    fn insert_identity(&self, identity: &Identity) -> anyhow::Result<()>;
    fn get_identity(&self, name: &str) -> anyhow::Result<Option<Identity>>;
    fn get_identity_by_key(&self, key_object_id: &uuid::Uuid) -> anyhow::Result<Vec<Identity>>;
    fn list_identities(&self) -> anyhow::Result<Vec<Identity>>;
    fn update_identity_key(
        &self,
        name: &str,
        new_key_object_id: &uuid::Uuid,
        rotated_from: &uuid::Uuid,
    ) -> anyhow::Result<()>;
    fn set_identity_cert(&self, name: &str, certificate_pem: &str) -> anyhow::Result<()>;
    fn delete_identity(&self, name: &str) -> anyhow::Result<bool>;

    /// Record the anti-rollback counter a checkpoint (by hex hash) was
    /// signed under.
    fn set_checkpoint_counter(&self, checkpoint_hash: &str, counter: u64) -> anyhow::Result<()>;

    /// Fetch the anti-rollback counter bound to a checkpoint hash.
    fn get_checkpoint_counter(&self, checkpoint_hash: &str) -> anyhow::Result<Option<u64>>;

    /// Highest anti-rollback counter recorded across all checkpoints, for
    /// detecting truncation against the live NV counter.
    fn max_checkpoint_counter(&self) -> anyhow::Result<Option<u64>>;
}
