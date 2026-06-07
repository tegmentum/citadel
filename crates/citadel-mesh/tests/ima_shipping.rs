//! C1 — runtime (IMA) evidence is shipped through the LtHash pipeline and the
//! PCR-10 append-only class is appraised via that log, not by value.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::PcrClass;
use citadel_mesh::runtime::{RuntimePolicy, RuntimeReason};
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        // Quote PCR 10 (IMA) so the Runtime-class test actually exercises it.
        pcr_selection: vec![0, 7, 10],
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

const IMA: &str = "\
10 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ima-ng sha256:1111111111111111111111111111111111111111111111111111111111111111 boot_aggregate
10 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ima-ng sha256:2222222222222222222222222222222222222222222222222222222222222222 /usr/bin/bash
10 cccccccccccccccccccccccccccccccccccccccc ima-ng sha256:3333333333333333333333333333333333333333333333333333333333333333 /usr/sbin/sshd
";

#[test]
fn ingesting_an_ima_log_preserves_it_in_the_lthash_pipeline() {
    let (mut mesh, ids) = mesh_of(2);
    let node = ids[0];

    let root_before = mesh.node(node).own_log_root();
    let (violations, ingested) = mesh.node_mut(node).ingest_own_ima(IMA);

    assert_eq!(ingested, 3, "all three IMA entries are ingested");
    assert!(violations.is_empty(), "no policy set → nothing flagged");
    // The runtime measurements are now in the durable, reconcilable log.
    assert_ne!(
        mesh.node(node).own_log_root(),
        root_before,
        "the LtHash root advanced"
    );
}

#[test]
fn ingest_appraises_against_the_runtime_policy() {
    let (mut mesh, ids) = mesh_of(2);
    let node = ids[0];
    // Denylist the bash hash from the IMA list above.
    mesh.node_mut(node)
        .set_runtime_policy(RuntimePolicy::new().deny("sha256", vec![0x11; 32]));

    let (violations, _) = mesh.node_mut(node).ingest_own_ima(IMA);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].reason, RuntimeReason::Denied);
    assert_eq!(violations[0].path, "boot_aggregate");
}

#[test]
fn a_growing_runtime_pcr_does_not_distrust() {
    // PCR 10 grows as files are measured at runtime; classed Runtime it is
    // appraised via the IMA log, so its changing *value* must not mint Unknown
    // (mirrors the Volatile case, but semantically "appraised elsewhere").
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    mesh.set_pcr_class_all(10, PcrClass::Runtime);
    mesh.measured_state_change(node, "sha256", 10, &[0xCD; 32]);
    mesh.run(12);

    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Trusted),
                "{observer} does not distrust {node} for a growing runtime PCR"
            );
        }
    }
}

#[test]
fn the_same_pcr10_change_distrusts_when_left_strict() {
    // Anchor: PCR 10 *is* quoted+appraised here, so the Runtime class (above) is
    // doing real work — left Strict, the identical change mints distrust.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    mesh.measured_state_change(node, "sha256", 10, &[0xCD; 32]);
    mesh.run(12);

    assert_eq!(
        mesh.trust_of(ids[0], node),
        Some(TrustState::Suspicious),
        "a Strict PCR-10 change is distrusted (proving PCR 10 is appraised)"
    );
}
