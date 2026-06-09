//! MSS2 + MSS3: mesh-governed secret release over gossip. A node requests a
//! secret; its assigned witnesses vote APPROVE iff they trust it; a quorum
//! authorizes release. Leases bound the grant; a node whose trust dropped is
//! denied at renewal (kept access mid-lease).

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

const SECRET: [u8; 32] = [0x5e; 32];

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
    // Everyone trusts everyone.
    assert_eq!(
        mesh.trust_of(workers[1], workers[0]),
        Some(TrustState::Trusted)
    );
    (mesh, workers)
}

#[test]
fn a_trusted_node_is_granted_release_by_quorum() {
    let (mut mesh, workers) = trusted_mesh();
    let requester = workers[0];

    // Request release: quorum 3 of an assigned set of 5, lease 100 ticks.
    let id = mesh
        .node_mut(requester)
        .request_release(SECRET, [1u8; 32], 3, 5, 100, 20);
    mesh.run(10);

    let now = mesh.node(requester).current_tick();
    assert!(
        mesh.node(requester).release_authorized(id, now),
        "quorum of trusting witnesses grants release"
    );
    // The authorization exists and carries the approving votes.
    let auth = mesh
        .node(requester)
        .release_authorization(id)
        .expect("authorized");
    assert!(auth.votes.iter().filter(|v| v.approve).count() >= 3);

    // Lease bounds it: far past the lease, the grant has expired (renewal needed).
    assert!(
        !mesh.node(requester).release_authorized(id, now + 200),
        "lease expires"
    );
}

#[test]
fn a_compromised_node_is_denied_at_renewal() {
    let (mut mesh, workers) = trusted_mesh();
    let requester = workers[0];

    // Healthy: granted.
    let first = mesh
        .node_mut(requester)
        .request_release(SECRET, [1u8; 32], 3, 5, 100, 20);
    mesh.run(10);
    let now = mesh.node(requester).current_tick();
    assert!(mesh.node(requester).release_authorized(first, now));

    // The node is compromised → witnesses see it Suspicious.
    mesh.measured_state_change(requester, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(
        mesh.trust_of(workers[1], requester),
        Some(TrustState::Suspicious)
    );

    // It keeps its existing lease (mid-lease access is not yanked)...
    let now2 = mesh.node(requester).current_tick();
    assert!(
        mesh.node(requester).release_authorized(first, now2),
        "existing lease held mid-lease"
    );

    // ...but renewal (a fresh request) is DENIED: the assigned witnesses now
    // refuse to approve, so no quorum forms.
    let renew = mesh
        .node_mut(requester)
        .request_release(SECRET, [2u8; 32], 3, 5, 100, now2 + 1);
    mesh.run(12);
    let now3 = mesh.node(requester).current_tick();
    assert!(
        !mesh.node(requester).release_authorized(renew, now3),
        "a node whose trust dropped is denied at renewal"
    );
}

#[test]
fn service_identity_is_a_mesh_released_secret_class() {
    use citadel_mesh::release::identity_secret_id;
    let (mut mesh, workers) = trusted_mesh();

    // A trusted node's service identity is released by quorum (it may mint).
    let good = workers[0];
    let id_ok =
        mesh.node_mut(good)
            .request_release(identity_secret_id(good), [7u8; 32], 3, 5, 100, 20);
    mesh.run(10);
    let now = mesh.node(good).current_tick();
    assert!(
        mesh.node(good).release_authorized(id_ok, now),
        "a trusted node may mint its mesh identity"
    );

    // A compromised node's identity is refused.
    let bad = workers[5];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(mesh.trust_of(workers[1], bad), Some(TrustState::Suspicious));
    let id_bad =
        mesh.node_mut(bad)
            .request_release(identity_secret_id(bad), [8u8; 32], 3, 5, 100, 40);
    mesh.run(12);
    let now2 = mesh.node(bad).current_tick();
    assert!(
        !mesh.node(bad).release_authorized(id_bad, now2),
        "a distrusted node cannot mint its identity"
    );
}

#[test]
fn bootstrap_class_serves_a_probationary_node() {
    const SECRET_B: [u8; 32] = [0xBC; 32];
    // Attestation off (witness_count 0) so trust doesn't churn; the secret's own
    // release quorum (n=5) is independent of attestation witnessing.
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 0,
        probe_interval: 1,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(8);

    // The requester is a freshly-(re)joined node: Probationary in every view
    // (the state a cold-starting node is in).
    let node = workers[0];
    for &w in &workers {
        mesh.node_mut(w).lift_quarantine(node, 8);
    }
    assert_eq!(
        mesh.trust_of(workers[1], node),
        Some(TrustState::Probationary)
    );

    // A bootstrap-class release is granted to a Probationary node...
    let boot = mesh
        .node_mut(node)
        .request_release_classed(SECRET_B, [1u8; 32], 3, 5, 100, true, 20);
    mesh.run(10);
    let now = mesh.node(node).current_tick();
    assert!(
        mesh.node(node).release_authorized(boot, now),
        "bootstrap class serves a probationary node"
    );

    // ...but a normal (Trusted-required) release is not.
    let normal =
        mesh.node_mut(node)
            .request_release_classed(SECRET, [2u8; 32], 3, 5, 100, false, now + 1);
    mesh.run(10);
    let now2 = mesh.node(node).current_tick();
    assert!(
        !mesh.node(node).release_authorized(normal, now2),
        "a high-value secret still needs Trusted"
    );
}
