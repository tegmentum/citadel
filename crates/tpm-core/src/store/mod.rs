pub mod memory;
pub mod traits;

#[cfg(feature = "sqlite")]
pub mod migrations;
#[cfg(feature = "sqlite")]
pub mod schema;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use memory::MemoryStore;
pub use traits::{
    AuditEntry, SecureLogRow, SecureLogSegmentRow, SecureLogStreamRow, StoreBackend,
    WitnessLogRow,
};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

use crate::model::{Identity, ObjectPath, Policy, Profile, TpmObject};

/// The workspace metadata store.
///
/// Wraps a `StoreBackend` implementation. On native targets with the
/// `sqlite` feature (default), use `Store::open()` for SQLite persistence.
/// On WASM or for tests, use `Store::memory()` for an in-memory backend.
pub struct Store {
    inner: Box<dyn StoreBackend>,
}

impl Store {
    /// Create a store backed by the given backend.
    pub fn new(backend: Box<dyn StoreBackend>) -> Self {
        Self { inner: backend }
    }

    /// Create an in-memory store (works everywhere, including WASM).
    pub fn memory() -> Self {
        Self {
            inner: Box::new(MemoryStore::new()),
        }
    }

    /// Open a SQLite-backed store at the given path.
    #[cfg(feature = "sqlite")]
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        Ok(Self {
            inner: Box::new(SqliteStore::open(path)?),
        })
    }

    /// Open an in-memory SQLite store (for tests that need SQL semantics).
    #[cfg(feature = "sqlite")]
    pub fn open_memory() -> anyhow::Result<Self> {
        Ok(Self {
            inner: Box::new(SqliteStore::open_memory()?),
        })
    }

    /// Alias for `memory()` when sqlite feature is not available.
    #[cfg(not(feature = "sqlite"))]
    pub fn open_memory() -> anyhow::Result<Self> {
        Ok(Self::memory())
    }

    // -- Delegation --

    pub fn insert_object(&self, obj: &TpmObject) -> anyhow::Result<()> {
        self.inner.insert_object(obj)
    }
    pub fn get_object(&self, path: &ObjectPath) -> anyhow::Result<Option<TpmObject>> {
        self.inner.get_object(path)
    }
    pub fn get_object_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<TpmObject>> {
        self.inner.get_object_by_id(id)
    }
    pub fn list_objects(&self) -> anyhow::Result<Vec<TpmObject>> {
        self.inner.list_objects()
    }
    pub fn delete_object(&self, path: &ObjectPath) -> anyhow::Result<bool> {
        self.inner.delete_object(path)
    }
    pub fn rename_object(
        &self,
        old_path: &ObjectPath,
        new_path: &ObjectPath,
    ) -> anyhow::Result<()> {
        self.inner.rename_object(old_path, new_path)
    }
    pub fn set_object_state(&self, path: &ObjectPath, state: &str) -> anyhow::Result<()> {
        self.inner.set_object_state(path, state)
    }
    pub fn touch_object(&self, path: &ObjectPath) -> anyhow::Result<()> {
        self.inner.touch_object(path)
    }
    pub fn object_count(&self) -> anyhow::Result<usize> {
        self.inner.object_count()
    }
    pub fn insert_profile(&self, profile: &Profile) -> anyhow::Result<()> {
        self.inner.insert_profile(profile)
    }
    pub fn get_active_profile(&self) -> anyhow::Result<Option<Profile>> {
        self.inner.get_active_profile()
    }
    pub fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        self.inner.list_profiles()
    }
    pub fn set_active_profile(&self, name: &str) -> anyhow::Result<()> {
        self.inner.set_active_profile(name)
    }
    pub fn insert_policy(&self, policy: &Policy) -> anyhow::Result<()> {
        self.inner.insert_policy(policy)
    }
    pub fn get_policy(&self, name: &str) -> anyhow::Result<Option<Policy>> {
        self.inner.get_policy(name)
    }
    pub fn get_policy_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<Policy>> {
        self.inner.get_policy_by_id(id)
    }
    pub fn list_policies(&self) -> anyhow::Result<Vec<Policy>> {
        self.inner.list_policies()
    }
    pub fn delete_policy(&self, name: &str) -> anyhow::Result<bool> {
        self.inner.delete_policy(name)
    }
    pub fn insert_nv_index(&self, name: &str, nv_index: u32, size: usize) -> anyhow::Result<()> {
        self.inner.insert_nv_index(name, nv_index, size)
    }
    pub fn get_nv_index(&self, name: &str) -> anyhow::Result<Option<(u32, usize)>> {
        self.inner.get_nv_index(name)
    }
    pub fn list_nv_indices(&self) -> anyhow::Result<Vec<(String, u32, usize)>> {
        self.inner.list_nv_indices()
    }
    pub fn nv_write_data(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        self.inner.nv_write_data(name, data)
    }
    pub fn nv_read_data(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner.nv_read_data(name)
    }
    pub fn delete_nv_index(&self, name: &str) -> anyhow::Result<bool> {
        self.inner.delete_nv_index(name)
    }
    pub fn save_pcr_baseline(
        &self,
        name: &str,
        bank: &str,
        values: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.inner.save_pcr_baseline(name, bank, values)
    }
    pub fn get_pcr_baseline(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<(String, serde_json::Value)>> {
        self.inner.get_pcr_baseline(name)
    }
    pub fn list_pcr_baselines(&self) -> anyhow::Result<Vec<String>> {
        self.inner.list_pcr_baselines()
    }
    pub fn log_action(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.inner.log_action(action, object_path, details)
    }
    pub fn log_action_with_correlation(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
        correlation_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .log_action_with_correlation(action, object_path, details, correlation_id)
    }
    pub fn list_audit_log(
        &self,
        filter_object: Option<&str>,
        filter_action: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEntry>> {
        self.inner
            .list_audit_log(filter_object, filter_action, limit)
    }
    pub fn insert_approval(
        &self,
        approval: &crate::model::ApprovalRequest,
    ) -> anyhow::Result<()> {
        self.inner.insert_approval(approval)
    }
    pub fn get_approval(
        &self,
        id: &uuid::Uuid,
    ) -> anyhow::Result<Option<crate::model::ApprovalRequest>> {
        self.inner.get_approval(id)
    }
    pub fn list_approvals(&self) -> anyhow::Result<Vec<crate::model::ApprovalRequest>> {
        self.inner.list_approvals()
    }
    pub fn update_approval_status(
        &self,
        id: &uuid::Uuid,
        status: crate::model::ApprovalStatus,
        resolved_by: Option<&str>,
    ) -> anyhow::Result<()> {
        self.inner.update_approval_status(id, status, resolved_by)
    }

    // -- Identities --

    pub fn insert_identity(&self, identity: &Identity) -> anyhow::Result<()> {
        self.inner.insert_identity(identity)
    }
    pub fn get_identity(&self, name: &str) -> anyhow::Result<Option<Identity>> {
        self.inner.get_identity(name)
    }
    pub fn get_identity_by_key(
        &self,
        key_object_id: &uuid::Uuid,
    ) -> anyhow::Result<Vec<Identity>> {
        self.inner.get_identity_by_key(key_object_id)
    }
    pub fn list_identities(&self) -> anyhow::Result<Vec<Identity>> {
        self.inner.list_identities()
    }
    pub fn update_identity_key(
        &self,
        name: &str,
        new_key_object_id: &uuid::Uuid,
        rotated_from: &uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.inner
            .update_identity_key(name, new_key_object_id, rotated_from)
    }
    pub fn set_identity_cert(&self, name: &str, certificate_pem: &str) -> anyhow::Result<()> {
        self.inner.set_identity_cert(name, certificate_pem)
    }
    pub fn delete_identity(&self, name: &str) -> anyhow::Result<bool> {
        self.inner.delete_identity(name)
    }

    // -- Secure log --

    pub fn secure_log_insert(&self, row: &SecureLogRow) -> anyhow::Result<u64> {
        self.inner.secure_log_insert(row)
    }
    pub fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>> {
        self.inner.secure_log_global_head()
    }
    pub fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<SecureLogRow>> {
        self.inner.secure_log_get(seqno)
    }
    pub fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<SecureLogRow>> {
        self.inner.secure_log_range(stream_id, from, to)
    }
    pub fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        self.inner.secure_log_head(stream_id)
    }
    pub fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<SecureLogRow>> {
        self.inner.secure_log_last(stream_id)
    }
    pub fn secure_log_segment_insert(
        &self,
        row: &SecureLogSegmentRow,
        entries: &[(u64, u64)],
    ) -> anyhow::Result<u64> {
        self.inner.secure_log_segment_insert(row, entries)
    }
    pub fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<SecureLogSegmentRow>> {
        self.inner.secure_log_segment_get(segment_id)
    }
    pub fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<SecureLogSegmentRow>> {
        self.inner.secure_log_segments_list(stream_id)
    }
    pub fn secure_log_segment_last_seqno(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        self.inner.secure_log_segment_last_seqno(stream_id)
    }
    pub fn secure_log_segment_entry_seqnos(&self, segment_id: u64) -> anyhow::Result<Vec<u64>> {
        self.inner.secure_log_segment_entry_seqnos(segment_id)
    }
    pub fn secure_log_segment_for_seqno(&self, seqno: u64) -> anyhow::Result<Option<u64>> {
        self.inner.secure_log_segment_for_seqno(seqno)
    }
    pub fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .secure_log_segment_set_signature(segment_id, signature, signer_identity)
    }
    pub fn witness_log_insert(&self, row: &WitnessLogRow) -> anyhow::Result<u64> {
        self.inner.witness_log_insert(row)
    }
    pub fn witness_log_latest(&self, stream_id: &str) -> anyhow::Result<Option<WitnessLogRow>> {
        self.inner.witness_log_latest(stream_id)
    }
    pub fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<WitnessLogRow>> {
        self.inner.witness_log_list(stream_id)
    }
    pub fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        self.inner.witness_log_stream_ids()
    }
    pub fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize> {
        self.inner
            .witness_log_gc(stream_id, keep_latest, older_than_rfc3339)
    }
    pub fn secure_log_stream_upsert(&self, row: &SecureLogStreamRow) -> anyhow::Result<()> {
        self.inner.secure_log_stream_upsert(row)
    }
    pub fn secure_log_stream_get(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<SecureLogStreamRow>> {
        self.inner.secure_log_stream_get(name)
    }
    pub fn secure_log_stream_list(&self) -> anyhow::Result<Vec<SecureLogStreamRow>> {
        self.inner.secure_log_stream_list()
    }
    pub fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()> {
        self.inner.secure_log_stream_set_tier(name, tier)
    }
    pub fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .secure_log_stream_deprecate(name, deprecated_at_rfc3339)
    }
}
