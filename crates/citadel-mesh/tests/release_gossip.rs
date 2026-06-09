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
