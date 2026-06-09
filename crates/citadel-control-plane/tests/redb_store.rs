//! RedbStore: the durable backend round-trips the verified facts, survives a
//! reopen, and drives a ControlPlane exactly like MemStore.

use std::sync::atomic::{AtomicU32, Ordering};

use citadel_control_plane::{ControlPlane, ControlPlaneStore, RedbStore};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_db() -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("citadel-redb-{}-{}.redb", std::process::id(), n))
}

#[test]
fn durable_store_persists_across_reopen() {
    let path = temp_db();

    // A mesh produces real verified facts via a ControlPlane over RedbStore.
    {
        let mut mesh = Mesh::new("prod-east-1");
        let cfg = NodeConfig {
            witness_count: 3,
            attestation_interval: 3,
            ..NodeConfig::default()
        };
        let workers: Vec<NodeId> = (1..=5)
            .map(|s| mesh.add_node(s, "worker", cfg.clone()))
            .collect();
        let observer = mesh.add_node(
            6,
            "control-plane",
            NodeConfig {
                observer: true,
                ..cfg.clone()
            },
        );
        mesh.wire_full_membership();
        mesh.run(20);

        let mut cp = ControlPlane::new(RedbStore::open(&path).unwrap());
        cp.observe(mesh.node_mut(observer), 20);
        // The fleet view is computed straight off the durable store.
        let h = cp.fleet_health();
        assert_eq!(h.total, workers.len());
        assert_eq!(h.trusted, workers.len());
        assert!(cp.nodes().len() == workers.len());
        for &w in &workers {
            assert_eq!(cp.node_view(&w).unwrap().trust, "trusted");
        }
    }

    // Reopen the same file in a fresh process-like scope: the facts are still
    // there (membership + verdicts persisted).
    {
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(store.all_nodes().len(), 6, "5 workers + observer persisted");
        let cp = ControlPlane::new(store);
        assert_eq!(
            cp.fleet_health().trusted,
            5,
            "trust re-derives from persisted verdicts"
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn durable_store_round_trips_events_and_audit() {
    use citadel_control_plane::{OperatorAuditEntry, TimelineEvent};
    let path = temp_db();
    {
        let mut s = RedbStore::open(&path).unwrap();
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
            detail: "trusted -> suspicious".into(),
        });
        s.append_event(TimelineEvent {
            tick: 9,
            subject: "xyz".into(),
            kind: "enrolled".into(),
            detail: String::new(),
        });
        s.append_operator_audit(OperatorAuditEntry {
            seq: 0,
            kind: "publish-policy".into(),
            target: "t".into(),
            operator: "op".into(),
            tick: 3,
            prev_hash: "00".into(),
            hash: "aa".into(),
        });
    }
    let s = RedbStore::open(&path).unwrap();
    assert_eq!(s.timeline_for("abc").len(), 2);
    assert_eq!(
        s.events_since(6).len(),
        2,
        "tick > 6 filters out the tick-5 event"
    );
    assert_eq!(s.operator_audit().len(), 1);
    assert_eq!(s.operator_audit()[0].kind, "publish-policy");
    let _ = std::fs::remove_file(&path);
}
