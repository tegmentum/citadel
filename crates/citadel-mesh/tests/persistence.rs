//! D2: durable evidence survives a restart (design `distributed-log-shipping-
//! lthash.md` §17). Nodes accumulate evidence (own log, replicated peer logs,
//! adopted manifests, audit chains, app appraisals), persist to a store, and a
//! freshly-constructed node of the same identity hydrates it back — while
//! transient membership/trust is NOT restored (re-earned via gossip).

use citadel_mesh::application::{AppId, AppMeasurement, AppPolicy};
use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::evidence::payload_hash;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{ArtifactIdentity, ReferenceEntry, ReferenceManifest, Validity};
use citadel_mesh::store::{FileStore, MemStore};
use citadel_mesh::{MeshKeypair, NodeId};

fn cfg() -> NodeConfig {
    NodeConfig { witness_count: 0, log_window_size: 8, ..NodeConfig::default() }
}

fn one_node(seed: u8) -> (Mesh, NodeId) {
    let mut mesh = Mesh::new("prod-east-1");
    let id = mesh.add_node(seed, "worker", cfg());
    mesh.wire_full_membership();
    (mesh, id)
}

#[test]
fn own_log_manifest_and_appraisals_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open(dir.path()).unwrap();

    let authority = MeshKeypair::from_seed([200u8; 32]);
    let manifest = ReferenceManifest::issue(
        &authority,
        "prod",
        vec![ReferenceEntry::new(0, b"kernel-v2".to_vec(), Validity::always())],
        vec![],
    );
    let manifest_id = manifest.content_id();

    let own_root;
    {
        // First "boot": accumulate evidence, persist.
        let (mut mesh, id) = one_node(1);
        let node = mesh.node_mut(id);
        node.set_reference_authorities(TrustAnchors::with(authority.public()));
        for i in 0..12u64 {
            node.append_event(payload_hash(format!("evt-{i}").as_bytes()));
        }
        own_root = node.own_log_root();

        assert!(node.apply_reference_manifest(&manifest));
        assert_eq!(node.reference_audit_len(), 1);

        let mut p = AppPolicy::new();
        p.accept(
            "billing",
            b"v2".to_vec(),
            ArtifactIdentity {
                component: "billing".into(),
                publisher: "acme".into(),
                channel: "prod".into(),
                version: vec![2, 0],
                build_id: None,
            },
        );
        node.set_app_policy(p);
        node.report_app(&AppMeasurement {
            app: AppId::new("billing"),
            digest: b"v2".to_vec(),
            version: vec![2, 0],
            role: "worker".into(),
            pcr_bound: false,
            timestamp_tick: 0,
        });

        node.persist(&store).unwrap();
    }

    // Second "boot": fresh node, same identity, hydrate.
    let (mut mesh2, id2) = one_node(1);
    {
        let node2 = mesh2.node_mut(id2);
        assert_ne!(node2.own_log_root(), own_root, "fresh node starts empty");
        assert!(node2.hydrate(&store).unwrap(), "snapshot present for this id");
    }

    let node2 = mesh2.node(id2);
    assert_eq!(node2.own_log_root(), own_root, "own log restored");
    assert_eq!(node2.reference_audit_len(), 1, "reference audit restored");
    assert!(node2.has_reference_manifest(manifest_id), "adopted manifest restored");
    assert!(node2.app_audit_len() >= 1, "app audit restored");
    assert!(node2.app_result_for(id2, "billing").is_some(), "app appraisal restored");
}

#[test]
fn a_replicated_peer_log_survives_a_restart() {
    // A two-node mesh: B replicates A's log. Persist B, then a fresh B hydrates
    // and still holds the replica of A.
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open(dir.path()).unwrap();

    let mut mesh = Mesh::new("prod-east-1");
    let rep_cfg = NodeConfig {
        witness_count: 0,
        log_window_size: 8,
        log_advertise_interval: 2,
        ..NodeConfig::default()
    };
    let a = mesh.add_node(1, "worker", rep_cfg.clone());
    let b = mesh.add_node(2, "worker", rep_cfg);
    mesh.wire_full_membership();
    for i in 0..16u64 {
        mesh.node_mut(a).append_event(payload_hash(format!("a-{i}").as_bytes()));
    }
    mesh.run(20);

    let a_root = mesh.node(a).own_log_root();
    assert_eq!(mesh.node(b).replica_root(a), Some(a_root.clone()), "B replicated A");
    mesh.node(b).persist(&store).unwrap();

    // Fresh B (same seed → same id) hydrates the replica.
    let mut mesh2 = Mesh::new("prod-east-1");
    let b2 = mesh2.add_node(2, "worker", NodeConfig { witness_count: 0, log_window_size: 8, ..NodeConfig::default() });
    assert_eq!(b2, b, "same seed yields the same identity");
    assert!(mesh2.node_mut(b2).hydrate(&store).unwrap());
    assert_eq!(mesh2.node(b2).replica_root(a), Some(a_root), "replica restored");
}

#[test]
fn hydrate_is_false_when_no_snapshot_exists() {
    let store = MemStore::new();
    let (mut mesh, id) = one_node(7);
    assert!(!mesh.node_mut(id).hydrate(&store).unwrap());
}

#[test]
fn snapshot_restore_roundtrips_in_memory() {
    let store = MemStore::new();
    let (mut mesh, id) = one_node(3);
    for i in 0..16u64 {
        mesh.node_mut(id).append_event(payload_hash(format!("x-{i}").as_bytes()));
    }
    mesh.node(id).persist(&store).unwrap();
    let root = mesh.node(id).own_log_root();

    let (mut mesh2, id2) = one_node(3);
    mesh2.node_mut(id2).hydrate(&store).unwrap();
    assert_eq!(mesh2.node(id2).own_log_root(), root);
}
