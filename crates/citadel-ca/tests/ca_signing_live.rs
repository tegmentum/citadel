//! CA1 live: a signing request is a mesh-released class — it runs the release
//! protocol, so the CA is asked to act only for a Trusted requester. A
//! compromised requester is denied before any signature.

use citadel_ca::signing_secret_id;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn trusted_mesh() -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(16);
    assert_eq!(
        mesh.trust_of(workers[1], workers[0]),
        Some(TrustState::Trusted)
    );
    (mesh, workers)
}

#[test]
fn signing_request_is_authorized_for_trusted_and_denied_for_compromised() {
    let (mut mesh, workers) = trusted_mesh();
    let digest = *blake3::hash(b"release: v1.2.3").as_bytes();

    // A trusted requester's signing request is authorized by quorum.
    let good = workers[0];
    let secret = signing_secret_id(good, &digest);
    let id = mesh
        .node_mut(good)
        .request_release(secret, [7u8; 32], 3, 5, 100, 20);
    mesh.run(10);
    let now = mesh.node(good).current_tick();
    assert!(
        mesh.node(good).release_authorized(id, now),
        "trusted → CA asked to sign"
    );

    // A compromised requester is denied — the CA is never asked to sign.
    let bad = workers[5];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(mesh.trust_of(workers[1], bad), Some(TrustState::Suspicious));
    let secret_b = signing_secret_id(bad, &digest);
    let id_b = mesh
        .node_mut(bad)
        .request_release(secret_b, [8u8; 32], 3, 5, 100, 40);
    mesh.run(12);
    let now2 = mesh.node(bad).current_tick();
    assert!(
        !mesh.node(bad).release_authorized(id_b, now2),
        "compromised → denied"
    );
}
