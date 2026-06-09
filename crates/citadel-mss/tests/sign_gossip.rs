//! MSS6b transport: the two FROST signing rounds run over **live mesh gossip**
//! (the generic AppRelay channel), gated by a release authorization. Holders
//! exchange only the public round messages; each keeps its key + nonces local.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;
use citadel_mss::session::{self, Round1Message, Round2Message};
use citadel_mss::tsig;

const SIGNING_SECRET: [u8; 32] = [0x51; 32];
const T1: [u8; 32] = [0xF1; 32]; // round-1 topic
const T2: [u8; 32] = [0xF2; 32]; // round-2 topic

#[test]
fn holders_threshold_sign_over_mesh_gossip() {
    // A 3-of-5 FROST signing key; one key package per holder node.
    let (public, packages) = tsig::keygen(3, 5).unwrap();

    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let nodes: Vec<NodeId> = (1..=5)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(16);

    // Gate: the mesh must authorize the signing operation's release first.
    let coordinator = nodes[0];
    let rel = mesh
        .node_mut(coordinator)
        .request_release(SIGNING_SECRET, [1u8; 32], 3, 5, 100, 20);
    mesh.run(10);
    assert!(
        mesh.node(coordinator)
            .release_authorized(rel, mesh.node(coordinator).current_tick()),
        "signing is gated on a mesh release authorization"
    );

    let message = b"issue-cert: cn=workload-7";
    let signers = 0..3; // 3 of the 5 holders participate

    // Round 1: each signer commits locally (keeps nonces) and broadcasts its
    // round-1 message over gossip.
    let mut nonces = Vec::new();
    let mut own_r1 = Vec::new();
    for i in signers.clone() {
        let (n, m) = session::round1(&packages[i]);
        nonces.push(n);
        own_r1.push(m.clone());
        mesh.node_mut(nodes[i]).broadcast_app(T1, m.to_bytes());
    }
    mesh.run(6);

    // Each signer assembles the round-1 set (peers' messages from gossip + its
    // own), builds the identical signing package, signs round 2, broadcasts share.
    let mut own_r2 = Vec::new();
    let mut my_package = Vec::new();
    for (idx, i) in signers.clone().enumerate() {
        let mut r1: Vec<Round1Message> = mesh
            .node_mut(nodes[i])
            .drain_app(T1)
            .iter()
            .map(|b| Round1Message::from_bytes(b).unwrap())
            .collect();
        r1.push(own_r1[idx].clone());
        let sp = session::signing_package(&r1, message);
        let r2 = session::round2(&sp, &nonces[idx], &packages[i]).unwrap();
        own_r2.push(r2.clone());
        my_package.push(sp);
        mesh.node_mut(nodes[i]).broadcast_app(T2, r2.to_bytes());
    }
    mesh.run(6);

    // The coordinator collects the round-2 shares from gossip + its own and
    // aggregates the group signature.
    let mut r2: Vec<Round2Message> = mesh
        .node_mut(nodes[0])
        .drain_app(T2)
        .iter()
        .map(|b| Round2Message::from_bytes(b).unwrap())
        .collect();
    r2.push(own_r2[0].clone());

    let sig = session::finish(&my_package[0], &r2, &public).unwrap();
    assert!(
        tsig::verify(&public, message, &sig),
        "gossip-orchestrated rounds yield a valid signature"
    );
    assert!(!tsig::verify(&public, b"tampered message", &sig));
}
