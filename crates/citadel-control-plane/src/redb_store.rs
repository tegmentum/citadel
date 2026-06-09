//! `RedbStore` — a durable [`ControlPlaneStore`] backed by [redb], an embedded,
//! pure-Rust ACID key-value store. No external service and no build-step beyond
//! `cargo` (keeps CI cargo-only), so it is the default durable backend for small
//! and medium fleets, and the per-shard local store under CP7.
//!
//! Values are stored as JSON (the same verified facts `MemStore` holds in RAM);
//! keys are raw `NodeId` bytes or a `u64` sequence. The trait is infallible, so a
//! storage error here is treated as deploy-fatal (`expect`) — a corrupt or
//! unwritable database is not a condition the aggregator can paper over.

use redb::{Database, ReadableTable, TableDefinition};
use serde::de::DeserializeOwned;
use serde::Serialize;

use citadel_mesh::evidence::EvidenceDurability;
use citadel_mesh::types::AttestationResult;
use citadel_mesh::NodeId;

use crate::model::{NodeRecord, TimelineEvent};
use crate::operator::OperatorAuditEntry;
use crate::store::ControlPlaneStore;

const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nodes");
const VERDICTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("verdicts");
const DURABILITY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("durability");
const EVENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("events");
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("operator_audit");

/// A durable control-plane store backed by an on-disk redb database.
pub struct RedbStore {
    db: Database,
}

fn enc<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("serializable")
}
fn dec<T: DeserializeOwned>(b: &[u8]) -> T {
    serde_json::from_slice(b).expect("stored value deserializes")
}

impl RedbStore {
    /// Open (creating if absent) a redb-backed store at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let db = Database::create(path)?;
        // Ensure every table exists so read transactions never hit a missing one.
        let w = db.begin_write()?;
        {
            w.open_table(NODES)?;
            w.open_table(VERDICTS)?;
            w.open_table(DURABILITY)?;
            w.open_table(EVENTS)?;
            w.open_table(AUDIT)?;
        }
        w.commit()?;
        Ok(RedbStore { db })
    }

    fn put_bytes(&self, table: TableDefinition<&[u8], &[u8]>, key: &[u8], val: &[u8]) {
        let w = self.db.begin_write().expect("redb write");
        {
            let mut t = w.open_table(table).expect("redb table");
            t.insert(key, val).expect("redb insert");
        }
        w.commit().expect("redb commit");
    }

    fn get_bytes<T: DeserializeOwned>(
        &self,
        table: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Option<T> {
        let r = self.db.begin_read().expect("redb read");
        let t = r.open_table(table).expect("redb table");
        t.get(key).expect("redb get").map(|g| dec(g.value()))
    }

    fn values<K: redb::Key + 'static, T: DeserializeOwned>(
        &self,
        table: TableDefinition<K, &[u8]>,
    ) -> Vec<T> {
        let r = self.db.begin_read().expect("redb read");
        let t = r.open_table(table).expect("redb table");
        t.iter()
            .expect("redb iter")
            .map(|row| {
                let (_, v) = row.expect("redb row");
                dec(v.value())
            })
            .collect()
    }
}

impl ControlPlaneStore for RedbStore {
    fn upsert_node(&mut self, node: NodeRecord) {
        let bytes = enc(&node);
        self.put_bytes(NODES, node.id.0.as_slice(), &bytes);
    }
    fn get_node(&self, id: &NodeId) -> Option<NodeRecord> {
        self.get_bytes(NODES, id.0.as_slice())
    }
    fn all_nodes(&self) -> Vec<NodeRecord> {
        self.values(NODES)
    }
    fn append_verdict(&mut self, verdict: AttestationResult) {
        let mut cur: Vec<AttestationResult> = self
            .get_bytes(VERDICTS, verdict.subject.0.as_slice())
            .unwrap_or_default();
        let key = verdict.subject.0;
        cur.push(verdict);
        let bytes = enc(&cur);
        self.put_bytes(VERDICTS, key.as_slice(), &bytes);
    }
    fn verdicts_for(&self, subject: &NodeId) -> Vec<AttestationResult> {
        self.get_bytes(VERDICTS, subject.0.as_slice())
            .unwrap_or_default()
    }
    fn replace_verdicts(&mut self, subject: &NodeId, verdicts: Vec<AttestationResult>) {
        let bytes = enc(&verdicts);
        self.put_bytes(VERDICTS, subject.0.as_slice(), &bytes);
    }
    fn prune_events(&mut self, before_tick: u64) {
        let w = self.db.begin_write().expect("redb write");
        {
            let mut t = w.open_table(EVENTS).expect("redb table");
            let remove: Vec<u64> = t
                .iter()
                .expect("redb iter")
                .filter_map(|row| {
                    let (k, v) = row.expect("redb row");
                    let e: TimelineEvent = dec(v.value());
                    (e.tick < before_tick).then_some(k.value())
                })
                .collect();
            for k in remove {
                t.remove(k).expect("redb remove");
            }
        }
        w.commit().expect("redb commit");
    }
    fn upsert_durability(&mut self, owner: NodeId, records: Vec<EvidenceDurability>) {
        let bytes = enc(&records);
        self.put_bytes(DURABILITY, owner.0.as_slice(), &bytes);
    }
    fn durability(&self, owner: &NodeId) -> Vec<EvidenceDurability> {
        self.get_bytes(DURABILITY, owner.0.as_slice())
            .unwrap_or_default()
    }
    fn append_event(&mut self, event: TimelineEvent) {
        let bytes = enc(&event);
        let w = self.db.begin_write().expect("redb write");
        {
            let mut t = w.open_table(EVENTS).expect("redb table");
            let seq = t
                .last()
                .expect("redb last")
                .map(|(k, _)| k.value() + 1)
                .unwrap_or(0);
            t.insert(seq, bytes.as_slice()).expect("redb insert");
        }
        w.commit().expect("redb commit");
    }
    fn timeline_for(&self, subject: &str) -> Vec<TimelineEvent> {
        self.values::<u64, TimelineEvent>(EVENTS)
            .into_iter()
            .filter(|e| e.subject == subject)
            .collect()
    }
    fn events_since(&self, since: u64) -> Vec<TimelineEvent> {
        self.values::<u64, TimelineEvent>(EVENTS)
            .into_iter()
            .filter(|e| e.tick > since)
            .collect()
    }
    fn append_operator_audit(&mut self, entry: OperatorAuditEntry) {
        let bytes = enc(&entry);
        let w = self.db.begin_write().expect("redb write");
        {
            let mut t = w.open_table(AUDIT).expect("redb table");
            t.insert(entry.seq, bytes.as_slice()).expect("redb insert");
        }
        w.commit().expect("redb commit");
    }
    fn operator_audit(&self) -> Vec<OperatorAuditEntry> {
        self.values::<u64, OperatorAuditEntry>(AUDIT)
    }
}
