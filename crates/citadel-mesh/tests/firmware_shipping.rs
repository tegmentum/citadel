//! B1 — the node's firmware measured-boot log is shipped through the LtHash
//! pipeline (`ingest_own_event_log`) and staged into the evidence it produces
//! (`stage_event_log`), so a verifier replays exactly what its firmware
//! measured. Mirrors the C1 IMA path in `ima_shipping.rs`.

use citadel_mesh::application::{AppId, AppMeasurement, AppPolicy};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::ArtifactIdentity;
use citadel_mesh::NodeId;
use tpm_core::eventlog::{BootEventLog, EventType, MeasurementEvent};

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig::default();
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

/// A small but realistic crypto-agile firmware log: a CRTM measurement into
/// PCR 0, a boot-services application into PCR 4, and a secure-boot variable
/// into PCR 7 — serialized as the Citadel wire form (`from_bytes` also accepts
/// raw TCG; both round-trip).
fn sample_event_log() -> Vec<u8> {
    let ev = |pcr: u32, ty: u32, digest: u8| MeasurementEvent {
        pcr,
        event_type: EventType::Unknown(ty),
        digests: vec![("sha256".to_string(), vec![digest; 32])],
        data: vec![],
    };
    BootEventLog::new(vec![
        ev(0, 0x0008, 0xa1),     // EV_S_CRTM_VERSION
        ev(4, 0x80000003, 0xb2), // EV_EFI_BOOT_SERVICES_APPLICATION
        ev(7, 0x80000001, 0xc3), // EV_EFI_VARIABLE_DRIVER_CONFIG
    ])
    .to_bytes()
}

#[test]
fn ingesting_a_firmware_log_preserves_it_in_the_lthash_pipeline() {
    let (mut mesh, ids) = mesh_of(2);
    let node = ids[0];

    let root_before = mesh.node(node).own_log_root();
    let ingested = mesh
        .node_mut(node)
        .ingest_own_event_log(&sample_event_log())
        .expect("the firmware log parses");

    assert_eq!(ingested, 3, "all three measured-boot events are ingested");
    assert_ne!(
        mesh.node(node).own_log_root(),
        root_before,
        "the LtHash root advanced — firmware evidence is now in the durable log"
    );
}

#[test]
fn ingest_is_deterministic_per_node() {
    // Same log ingested into the same node twice (fresh each time) yields the
    // same advanced root — the per-event element is a stable function of the
    // log, so peers reconcile.
    let log = sample_event_log();
    let root = |seed: u8| {
        let mut mesh = Mesh::new("prod-east-1");
        let id = mesh.add_node(seed, "worker", NodeConfig::default());
        mesh.node_mut(id).ingest_own_event_log(&log).unwrap();
        mesh.node(id).own_log_root()
    };
    assert_eq!(root(1), root(1), "ingest is deterministic for a given node");
}

#[test]
fn a_garbage_log_is_a_clean_error_not_a_panic() {
    let (mut mesh, ids) = mesh_of(1);
    let err = mesh
        .node_mut(ids[0])
        .ingest_own_event_log(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(err.is_err(), "undecodable bytes return Err, not panic");
}

#[test]
fn staged_firmware_log_binds_this_nodes_own_app_measurements() {
    // The staged firmware log is what this node verifies its own pcr_bound app
    // measurements against (B1): a measurement whose digest the firmware log
    // measured into PCR 10 stays bound (full confidence); without that log the
    // claim is downgraded to advisory.
    let (mut mesh, ids) = mesh_of(1);
    let node = ids[0];
    let digest = vec![0x5a; 32];

    // Register the app + accepted digest so the verdict is Healthy and the
    // confidence tracks the (validated) pcr_bound flag.
    let mut policy = AppPolicy::new();
    policy.accept("billing-api", digest.clone(), artifact(vec![1, 0]));
    policy.allow_role("billing-api", "worker");
    mesh.node_mut(node).set_app_policy(policy);

    let m = AppMeasurement {
        app: AppId::new("billing-api"),
        digest: digest.clone(),
        version: vec![1, 0],
        role: "worker".to_string(),
        pcr_bound: true,
        timestamp_tick: 1,
    };

    // No firmware log staged: the backend's synthesized log doesn't measure this
    // digest into PCR 10 → the pcr_bound claim is downgraded → advisory (0.5).
    let advisory = mesh.node(node).appraise_app(&m).confidence;

    // Stage a firmware log that measures the digest into PCR 10 → bound → 1.0.
    let log = BootEventLog::new(vec![MeasurementEvent {
        pcr: 10,
        event_type: EventType::Unknown(0x000d), // EV_IPL
        digests: vec![("sha256".to_string(), digest.clone())],
        data: vec![],
    }])
    .to_bytes();
    mesh.node_mut(node).stage_event_log(&log);
    let bound = mesh.node(node).appraise_app(&m).confidence;

    assert!(
        advisory < bound,
        "the staged firmware log binds the measurement (advisory {advisory} < bound {bound})"
    );
    assert_eq!(bound, 1.0, "a firmware-measured digest is fully bound");
}

fn artifact(version: Vec<u64>) -> ArtifactIdentity {
    ArtifactIdentity {
        component: "billing-api".into(),
        publisher: "acme".into(),
        channel: "prod".into(),
        version,
        build_id: None,
    }
}
