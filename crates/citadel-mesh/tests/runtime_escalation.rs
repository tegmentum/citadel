//! C1 integration — runtime (IMA) policy violations drive node trust.
//! A known-bad file executing on a node escalates it to distrust, the
//! escalation is sticky against a clean platform re-quote, and it survives a
//! restart (persisted like an app escalation).

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::runtime::{RuntimePolicy, RuntimeReason};
use citadel_mesh::state::TrustState;
use citadel_mesh::store::MemStore;
use citadel_mesh::NodeId;

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig { witness_count: 3, attestation_interval: 3, ..NodeConfig::default() };
    let ids: Vec<NodeId> = (1..=n).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

// A clean IMA list (just the boot aggregate) and one with a known-bad binary.
const CLEAN: &str =
    "10 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ima-ng sha256:1111111111111111111111111111111111111111111111111111111111111111 boot_aggregate";
fn with_evil() -> String {
    format!(
        "{CLEAN}\n10 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ima-ng sha256:{} /tmp/cryptominer\n",
        "ee".repeat(32)
    )
}
fn evil_hash() -> Vec<u8> {
    vec![0xee; 32]
}

#[test]
fn a_known_bad_file_executing_distrusts_the_node() {
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let verifier = ids[0];
    let subject = ids[4];

    // Everyone trusted to begin with.
    assert_eq!(mesh.trust_of(verifier, subject), Some(TrustState::Trusted));

    // The fleet denylists a known-bad binary hash.
    mesh.set_runtime_policy_all(RuntimePolicy::new().deny("sha256", evil_hash()));

    // A clean runtime list keeps the node trusted...
    let v = mesh.report_runtime(verifier, subject, CLEAN);
    assert!(v.is_empty());
    assert_eq!(mesh.trust_of(verifier, subject), Some(TrustState::Trusted));

    // ...but the denylisted binary executing escalates it to distrust.
    let v = mesh.report_runtime(verifier, subject, &with_evil());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].reason, RuntimeReason::Denied);
    assert_eq!(v[0].path, "/tmp/cryptominer");
    assert_eq!(
        mesh.trust_of(verifier, subject),
        Some(TrustState::Suspicious),
        "a known-bad file that ran distrusts the node"
    );
}

#[test]
fn runtime_escalation_is_sticky_against_a_clean_requote() {
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let verifier = ids[0];
    let subject = ids[4];

    mesh.set_runtime_policy_all(RuntimePolicy::new().deny("sha256", evil_hash()));
    mesh.report_runtime(verifier, subject, &with_evil());
    assert_eq!(mesh.trust_of(verifier, subject), Some(TrustState::Suspicious));

    // The platform keeps producing pristine boot quotes — runtime integrity
    // failed regardless, so trust must NOT silently recover.
    mesh.run(24);
    assert_eq!(
        mesh.trust_of(verifier, subject),
        Some(TrustState::Suspicious),
        "a clean boot quote must not clear a runtime-integrity escalation"
    );
}

#[test]
fn runtime_escalation_survives_a_restart() {
    let (mut mesh, ids) = mesh_of(2);
    let verifier = ids[0];
    let subject = ids[1];
    mesh.set_runtime_policy_all(RuntimePolicy::new().deny("sha256", evil_hash()));
    mesh.report_runtime(verifier, subject, &with_evil());
    assert!(mesh.node(verifier).runtime_escalated(subject));

    let store = MemStore::new();
    mesh.node_mut(verifier).persist(&store).unwrap();

    // A fresh node hydrates the persisted escalation.
    let mut fresh = Mesh::new("prod-east-1");
    let cfg = NodeConfig { witness_count: 3, attestation_interval: 3, ..NodeConfig::default() };
    fresh.add_node(1, "worker", cfg);
    assert!(fresh.node_mut(verifier).hydrate(&store).unwrap(), "snapshot present");
    assert!(
        fresh.node(verifier).runtime_escalated(subject),
        "the runtime escalation is restored on restart, not silently cleared"
    );
}
