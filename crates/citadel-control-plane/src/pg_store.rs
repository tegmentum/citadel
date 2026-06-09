//! `PgStore` — a Postgres-backed durable [`ControlPlaneStore`] for CP7 (HA +
//! 10k-node scale). Feature-gated (`postgres-store`): it pulls the blocking
//! `postgres` client and needs a live database, so it is off by default and its
//! test is `#[ignore]`d (run it with `CITADEL_PG_TEST_URL` set).
//!
//! Why this shape: current-state rows (`nodes`, `durability`) give hot keyed
//! reads; `verdicts`/`events` are append tables with `subject`/`tick` indexes for
//! the per-subject and `since`-cursor scans; `operator_audit` is the ordered
//! hash-chain. At scale these become the natural seams for CP7 — read replicas
//! for the scaled read API, partition/`TimescaleDB` continuous-aggregates for the
//! steady-state rollup + retention, observers sharded by HRW subject-space. The
//! blocking client lives behind a `Mutex` because its query methods need `&mut`
//! while the store trait reads through `&self`.
//!
//! Values are JSON text (the same verified facts the in-memory store holds); the
//! trait is infallible, so a database error is treated as deploy-fatal.

use std::sync::Mutex;

use postgres::{Client, NoTls};
use serde::de::DeserializeOwned;
use serde::Serialize;

use citadel_mesh::evidence::EvidenceDurability;
use citadel_mesh::types::AttestationResult;
use citadel_mesh::NodeId;

use crate::model::{NodeRecord, TimelineEvent};
use crate::operator::OperatorAuditEntry;
use crate::store::ControlPlaneStore;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS nodes (node_id BYTEA PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS verdicts (seq BIGSERIAL PRIMARY KEY, subject BYTEA NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS verdicts_subject ON verdicts(subject);
CREATE TABLE IF NOT EXISTS durability (owner BYTEA PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (seq BIGSERIAL PRIMARY KEY, subject TEXT NOT NULL, tick BIGINT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_tick ON events(tick);
CREATE INDEX IF NOT EXISTS events_subject ON events(subject);
CREATE TABLE IF NOT EXISTS operator_audit (seq BIGINT PRIMARY KEY, data TEXT NOT NULL);
";

/// A durable control-plane store over Postgres.
pub struct PgStore {
    client: Mutex<Client>,
}

fn enc<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serializable")
}
fn dec<T: DeserializeOwned>(s: &str) -> T {
    serde_json::from_str(s).expect("stored value deserializes")
}

impl PgStore {
    /// Connect to Postgres at `url` and ensure the schema exists.
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let mut client = Client::connect(url, NoTls)?;
        client.batch_execute(SCHEMA)?;
        Ok(PgStore {
            client: Mutex::new(client),
        })
    }

    fn exec(&self, sql: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) {
        self.client
            .lock()
            .unwrap()
            .execute(sql, params)
            .expect("pg execute");
    }

    fn json_rows<T: DeserializeOwned>(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Vec<T> {
        self.client
            .lock()
            .unwrap()
            .query(sql, params)
            .expect("pg query")
            .iter()
            .map(|r| dec(r.get::<_, &str>(0)))
            .collect()
    }
}

impl ControlPlaneStore for PgStore {
    fn upsert_node(&mut self, node: NodeRecord) {
        self.exec(
            "INSERT INTO nodes (node_id, data) VALUES ($1, $2)
             ON CONFLICT (node_id) DO UPDATE SET data = EXCLUDED.data",
            &[&&node.id.0[..], &enc(&node)],
        );
    }
    fn get_node(&self, id: &NodeId) -> Option<NodeRecord> {
        self.json_rows("SELECT data FROM nodes WHERE node_id = $1", &[&&id.0[..]])
            .into_iter()
            .next()
    }
    fn all_nodes(&self) -> Vec<NodeRecord> {
        self.json_rows("SELECT data FROM nodes", &[])
    }
    fn append_verdict(&mut self, verdict: AttestationResult) {
        self.exec(
            "INSERT INTO verdicts (subject, data) VALUES ($1, $2)",
            &[&&verdict.subject.0[..], &enc(&verdict)],
        );
    }
    fn verdicts_for(&self, subject: &NodeId) -> Vec<AttestationResult> {
        self.json_rows(
            "SELECT data FROM verdicts WHERE subject = $1 ORDER BY seq",
            &[&&subject.0[..]],
        )
    }
    fn replace_verdicts(&mut self, subject: &NodeId, verdicts: Vec<AttestationResult>) {
        let mut c = self.client.lock().unwrap();
        let mut tx = c.transaction().expect("pg tx");
        tx.execute(
            "DELETE FROM verdicts WHERE subject = $1",
            &[&&subject.0[..]],
        )
        .expect("pg delete");
        for v in &verdicts {
            tx.execute(
                "INSERT INTO verdicts (subject, data) VALUES ($1, $2)",
                &[&&subject.0[..], &enc(v)],
            )
            .expect("pg insert");
        }
        tx.commit().expect("pg commit");
    }
    fn prune_events(&mut self, before_tick: u64) {
        self.exec(
            "DELETE FROM events WHERE tick < $1",
            &[&(before_tick as i64)],
        );
    }
    fn upsert_durability(&mut self, owner: NodeId, records: Vec<EvidenceDurability>) {
        self.exec(
            "INSERT INTO durability (owner, data) VALUES ($1, $2)
             ON CONFLICT (owner) DO UPDATE SET data = EXCLUDED.data",
            &[&&owner.0[..], &enc(&records)],
        );
    }
    fn durability(&self, owner: &NodeId) -> Vec<EvidenceDurability> {
        self.json_rows(
            "SELECT data FROM durability WHERE owner = $1",
            &[&&owner.0[..]],
        )
        .into_iter()
        .next()
        .unwrap_or_default()
    }
    fn append_event(&mut self, event: TimelineEvent) {
        self.exec(
            "INSERT INTO events (subject, tick, data) VALUES ($1, $2, $3)",
            &[&event.subject, &(event.tick as i64), &enc(&event)],
        );
    }
    fn timeline_for(&self, subject: &str) -> Vec<TimelineEvent> {
        self.json_rows(
            "SELECT data FROM events WHERE subject = $1 ORDER BY seq",
            &[&subject],
        )
    }
    fn events_since(&self, since: u64) -> Vec<TimelineEvent> {
        self.json_rows(
            "SELECT data FROM events WHERE tick > $1 ORDER BY seq",
            &[&(since as i64)],
        )
    }
    fn append_operator_audit(&mut self, entry: OperatorAuditEntry) {
        self.exec(
            "INSERT INTO operator_audit (seq, data) VALUES ($1, $2)
             ON CONFLICT (seq) DO UPDATE SET data = EXCLUDED.data",
            &[&(entry.seq as i64), &enc(&entry)],
        );
    }
    fn operator_audit(&self) -> Vec<OperatorAuditEntry> {
        self.json_rows("SELECT data FROM operator_audit ORDER BY seq", &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TimelineEvent;
    use citadel_mesh::crypto::MeshKeypair;
    use citadel_mesh::state::LivenessState;

    // Opt-in: set CITADEL_PG_TEST_URL to a throwaway database, then run with
    // `cargo test -p citadel-control-plane --features postgres-store -- --ignored`.
    #[test]
    #[ignore = "requires CITADEL_PG_TEST_URL + a live Postgres"]
    fn round_trips_against_a_live_postgres() {
        let url = std::env::var("CITADEL_PG_TEST_URL").expect("CITADEL_PG_TEST_URL");
        let mut s = PgStore::connect(&url).unwrap();
        s.client
            .lock()
            .unwrap()
            .batch_execute("TRUNCATE nodes, verdicts, durability, events, operator_audit")
            .unwrap();

        let id = NodeId([3; 32]);
        s.upsert_node(NodeRecord {
            id,
            public_key: MeshKeypair::from_seed([3; 32]).public(),
            role: "worker".into(),
            liveness: LivenessState::Alive,
            observer: false,
            last_seen_tick: 1,
        });
        assert_eq!(s.all_nodes().len(), 1);
        assert!(s.get_node(&id).is_some());

        s.append_event(TimelineEvent {
            tick: 5,
            subject: "abc".into(),
            kind: "enrolled".into(),
            detail: String::new(),
        });
        s.append_event(TimelineEvent {
            tick: 9,
            subject: "abc".into(),
            kind: "trust-transition".into(),
            detail: "x".into(),
        });
        assert_eq!(s.timeline_for("abc").len(), 2);
        assert_eq!(s.events_since(6).len(), 1);

        s.append_operator_audit(OperatorAuditEntry {
            seq: 0,
            kind: "publish-policy".into(),
            target: "t".into(),
            operator: "op".into(),
            tick: 3,
            prev_hash: "00".into(),
            hash: "aa".into(),
        });
        assert_eq!(s.operator_audit().len(), 1);
    }
}
