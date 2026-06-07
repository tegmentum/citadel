pub mod memory;
pub mod traits;

#[cfg(feature = "sqlite")]
pub mod migrations;
#[cfg(feature = "sqlite")]
pub mod schema;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use memory::MemoryStore;
pub use traits::{AuditEntry, StoreBackend};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

// Re-export the secure-log row types from the extracted crate so
// existing `use tpm_core::store::{SecureLogRow, ...}` import paths
// keep working.
pub use ::secure_log::{
    SecureLogRow, SecureLogSegmentRow, SecureLogStore, SecureLogStreamRow, WitnessLogRow,
};

#[cfg(feature = "sqlite")]
use secure_log_sqlite::SqliteSecureLogStore;

use crate::model::{Identity, ObjectPath, Policy, Profile, TpmObject};

/// Open one connection to a named shared-cache in-memory database.
///
/// Both the main store and the secure-log store call this with the
/// same URI so they co-inhabit a single in-memory database (see
/// [`Store::open_memory`]). The `mode=memory&cache=shared` URI is only
/// honored when the connection is opened with `SQLITE_OPEN_URI`.
#[cfg(feature = "sqlite")]
fn open_shared_memory_conn(uri: &str) -> anyhow::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}

/// The workspace metadata store.
///
/// Wraps a `StoreBackend` implementation. On native targets with the
/// `sqlite` feature (default), use `Store::open()` for SQLite persistence.
/// On WASM or for tests, use `Store::memory()` for an in-memory backend.
///
/// SQLite-backed stores additionally hold a sibling
/// [`SqliteSecureLogStore`] connection for the tamper-evident audit
/// log, exposed via the `secure_log_*` / `witness_log_*` delegation
/// methods. Memory-backed stores do not provide secure-log
/// functionality — those methods will panic if called on a memory
/// store. This matches the prior contract, where the secure-log
/// tables only existed under the SQLite schema.
pub struct Store {
    inner: Box<dyn StoreBackend>,
    #[cfg(feature = "sqlite")]
    secure_log: Option<SqliteSecureLogStore>,
}

impl Store {
    /// Create a store backed by the given backend.
    ///
    /// The secure-log side is left disabled; use `Store::open()` for
    /// a fully-functional SQLite-backed store.
    pub fn new(backend: Box<dyn StoreBackend>) -> Self {
        Self {
            inner: backend,
            #[cfg(feature = "sqlite")]
            secure_log: None,
        }
    }

    /// Create an in-memory store (works everywhere, including WASM).
    ///
    /// Memory stores do not provide secure-log functionality.
    pub fn memory() -> Self {
        Self {
            inner: Box::new(MemoryStore::new()),
            #[cfg(feature = "sqlite")]
            secure_log: None,
        }
    }

    /// Open a SQLite-backed store at the given path.
    #[cfg(feature = "sqlite")]
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let inner: Box<dyn StoreBackend> = Box::new(SqliteStore::open(path)?);
        let secure_log = SqliteSecureLogStore::open(path)?;
        Ok(Self {
            inner,
            secure_log: Some(secure_log),
        })
    }

    /// Open an in-memory SQLite store (for tests that need SQL semantics).
    ///
    /// The main store and the secure-log store share a single
    /// shared-cache in-memory database, so they see each other's rows
    /// just like the file-backed [`Store::open`] (where both open the
    /// same file). A unique cache name per call keeps independent
    /// in-memory stores isolated from one another; the database lives
    /// as long as either connection is open, and this `Store` holds
    /// both for its lifetime.
    #[cfg(feature = "sqlite")]
    pub fn open_memory() -> anyhow::Result<Self> {
        let uri = format!(
            "file:citadel-mem-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        let inner = SqliteStore::from_connection(open_shared_memory_conn(&uri)?)?;
        let secure_log = SqliteSecureLogStore::from_connection(open_shared_memory_conn(&uri)?)?;
        Ok(Self {
            inner: Box::new(inner),
            secure_log: Some(secure_log),
        })
    }

    /// Alias for `memory()` when sqlite feature is not available.
    #[cfg(not(feature = "sqlite"))]
    pub fn open_memory() -> anyhow::Result<Self> {
        Ok(Self::memory())
    }

    /// Borrow the sibling secure-log store.
    ///
    /// Returns an error if this `Store` was created without a SQLite
    /// backend (i.e. via `Store::new` with a custom backend or via
    /// `Store::memory()`). All secure-log / witness-log forwards go
    /// through here, so they surface the same error rather than
    /// panicking.
    #[cfg(feature = "sqlite")]
    pub fn secure_log_store(&self) -> anyhow::Result<&SqliteSecureLogStore> {
        self.secure_log.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "secure-log store is only available on SQLite-backed Store \
                 instances; use Store::open(path) or Store::open_memory()"
            )
        })
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
    pub fn insert_approval(&self, approval: &crate::model::ApprovalRequest) -> anyhow::Result<()> {
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
    pub fn get_identity_by_key(&self, key_object_id: &uuid::Uuid) -> anyhow::Result<Vec<Identity>> {
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

    pub fn set_checkpoint_counter(
        &self,
        checkpoint_hash: &str,
        counter: u64,
    ) -> anyhow::Result<()> {
        self.inner.set_checkpoint_counter(checkpoint_hash, counter)
    }

    pub fn get_checkpoint_counter(&self, checkpoint_hash: &str) -> anyhow::Result<Option<u64>> {
        self.inner.get_checkpoint_counter(checkpoint_hash)
    }

    pub fn max_checkpoint_counter(&self) -> anyhow::Result<Option<u64>> {
        self.inner.max_checkpoint_counter()
    }

    // -- Secure log delegation --
    //
    // All methods below forward to the sibling SqliteSecureLogStore
    // owned by this Store, returning an error (via `secure_log_store`)
    // if it was constructed without a SQLite backend. The extracted
    // `secure-log` crate is the authoritative implementation; these
    // methods are kept on Store for backward compatibility with
    // existing call sites.

    #[cfg(feature = "sqlite")]
    pub fn secure_log_insert(&self, row: &SecureLogRow) -> anyhow::Result<u64> {
        self.secure_log_store()?.secure_log_insert(row)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>> {
        self.secure_log_store()?.secure_log_global_head()
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<SecureLogRow>> {
        self.secure_log_store()?.secure_log_get(seqno)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<SecureLogRow>> {
        self.secure_log_store()?
            .secure_log_range(stream_id, from, to)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        self.secure_log_store()?.secure_log_head(stream_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<SecureLogRow>> {
        self.secure_log_store()?.secure_log_last(stream_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segment_insert(
        &self,
        row: &SecureLogSegmentRow,
        entries: &[(u64, u64)],
    ) -> anyhow::Result<u64> {
        self.secure_log_store()?
            .secure_log_segment_insert(row, entries)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<SecureLogSegmentRow>> {
        self.secure_log_store()?.secure_log_segment_get(segment_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<SecureLogSegmentRow>> {
        self.secure_log_store()?.secure_log_segments_list(stream_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segment_last_seqno(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        self.secure_log_store()?
            .secure_log_segment_last_seqno(stream_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segment_entry_seqnos(&self, segment_id: u64) -> anyhow::Result<Vec<u64>> {
        self.secure_log_store()?
            .secure_log_segment_entry_seqnos(segment_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segment_for_seqno(&self, seqno: u64) -> anyhow::Result<Option<u64>> {
        self.secure_log_store()?.secure_log_segment_for_seqno(seqno)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()> {
        self.secure_log_store()?.secure_log_segment_set_signature(
            segment_id,
            signature,
            signer_identity,
        )
    }
    #[cfg(feature = "sqlite")]
    pub fn witness_log_insert(&self, row: &WitnessLogRow) -> anyhow::Result<u64> {
        self.secure_log_store()?.witness_log_insert(row)
    }
    #[cfg(feature = "sqlite")]
    pub fn witness_log_latest(&self, stream_id: &str) -> anyhow::Result<Option<WitnessLogRow>> {
        self.secure_log_store()?.witness_log_latest(stream_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<WitnessLogRow>> {
        self.secure_log_store()?.witness_log_list(stream_id)
    }
    #[cfg(feature = "sqlite")]
    pub fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        self.secure_log_store()?.witness_log_stream_ids()
    }
    #[cfg(feature = "sqlite")]
    pub fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize> {
        self.secure_log_store()?
            .witness_log_gc(stream_id, keep_latest, older_than_rfc3339)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_stream_upsert(&self, row: &SecureLogStreamRow) -> anyhow::Result<()> {
        self.secure_log_store()?.secure_log_stream_upsert(row)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_stream_get(&self, name: &str) -> anyhow::Result<Option<SecureLogStreamRow>> {
        self.secure_log_store()?.secure_log_stream_get(name)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_stream_list(&self) -> anyhow::Result<Vec<SecureLogStreamRow>> {
        self.secure_log_store()?.secure_log_stream_list()
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()> {
        self.secure_log_store()?
            .secure_log_stream_set_tier(name, tier)
    }
    #[cfg(feature = "sqlite")]
    pub fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()> {
        self.secure_log_store()?
            .secure_log_stream_deprecate(name, deprecated_at_rfc3339)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    fn stream_row(name: &str) -> SecureLogStreamRow {
        SecureLogStreamRow {
            name: name.to_string(),
            tier: "public".to_string(),
            description: None,
            created_at_rfc3339: "2026-01-01T00:00:00Z".to_string(),
            deprecated_at_rfc3339: None,
        }
    }

    /// A `Store` without a SQLite backend has no secure-log; forwards
    /// must surface a clean error instead of panicking.
    #[test]
    fn memory_store_secure_log_forward_errors_not_panics() {
        let store = Store::memory();
        let err = store
            .secure_log_global_head()
            .expect_err("secure-log forward should error on a memory store");
        assert!(
            err.to_string().contains("SQLite-backed"),
            "unexpected error message: {err}"
        );
        // The dedicated accessor reports the same condition.
        assert!(store.secure_log_store().is_err());
    }

    /// `open_memory` wires up a working secure-log store: rows written
    /// through the forwards survive a read-back on the same `Store`.
    #[test]
    fn open_memory_secure_log_round_trips() {
        let store = Store::open_memory().unwrap();
        store
            .secure_log_stream_upsert(&stream_row("alpha"))
            .unwrap();
        let got = store.secure_log_stream_get("alpha").unwrap();
        assert_eq!(got.map(|r| r.name), Some("alpha".to_string()));
    }

    /// Each `open_memory` call gets a uniquely-named shared cache, so
    /// two in-memory stores never leak rows into one another (a fixed
    /// cache name would cross-contaminate tests).
    #[test]
    fn open_memory_instances_are_isolated() {
        let a = Store::open_memory().unwrap();
        let b = Store::open_memory().unwrap();
        a.secure_log_stream_upsert(&stream_row("only-in-a"))
            .unwrap();
        assert!(a.secure_log_stream_get("only-in-a").unwrap().is_some());
        assert!(
            b.secure_log_stream_get("only-in-a").unwrap().is_none(),
            "second in-memory store should not see the first store's rows"
        );
    }
}
