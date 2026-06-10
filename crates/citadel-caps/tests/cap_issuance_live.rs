//! CAP2 live: a capability request is a mesh-released class — it runs the release
//! protocol (request → assigned-witness vote → quorum authorization), so a
//! Trusted node is granted and a compromised one is denied at the next request.

use citadel_caps::capability_secret_id;
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
fn capability_is_granted_to_a_trusted_node_and_denied_to_a_compromised_one() {
    let (mut mesh, workers) = trusted_mesh();

    // A trusted node's capability request is authorized by quorum.
    let good = workers[0];
    let secret = capability_secret_id(good, "deploy:prod");
    let id = mesh
        .node_mut(good)
        .request_release(secret, [7u8; 32], 3, 5, 100, 20);
    mesh.run(10);
    let now = mesh.node(good).current_tick();
    assert!(
        mesh.node(good).release_authorized(id, now),
        "trusted node → capability authorized"
    );

    // A compromised node's capability request is denied (deny-at-renewal).
    let bad = workers[5];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(mesh.trust_of(workers[1], bad), Some(TrustState::Suspicious));
    let secret_b = capability_secret_id(bad, "deploy:prod");
    let id_b = mesh
        .node_mut(bad)
        .request_release(secret_b, [8u8; 32], 3, 5, 100, 40);
    mesh.run(12);
    let now2 = mesh.node(bad).current_tick();
    assert!(
        !mesh.node(bad).release_authorized(id_b, now2),
        "compromised node → capability denied"
    );
}
