//! MB2: a beacon round gossips over the mesh AppRelay channel and every peer
//! adopts the same verified freshness anchor.

use citadel_beacon::{BeaconRound, BeaconState, BEACON_TOPIC, GENESIS_PREV};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;
use citadel_mss::tsig;

#[test]
fn beacon_round_gossips_and_peers_adopt() {
    // A 3-of-5 beacon group; produce the genesis round.
    let (public, packages) = tsig::keygen(3, 5).unwrap();
    let r0 = BeaconRound::produce(0, GENESIS_PREV, &packages[0..3], &public).unwrap();

    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let nodes: Vec<NodeId> = (1..=4)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(8);

    // A beacon holder broadcasts the round over AppRelay.
    mesh.node_mut(nodes[0])
        .broadcast_app(BEACON_TOPIC, r0.to_bytes());
    mesh.run(6);

    // Every peer drains + adopts the verified round → the same freshness value.
    for &n in &nodes[1..] {
        let mut state = BeaconState::new(public.clone());
        assert!(
            state.ingest(&mesh.node_mut(n).drain_app(BEACON_TOPIC)),
            "peer adopts the round"
        );
        assert_eq!(state.round(), 0);
        assert_eq!(state.value(), Some(r0.value()), "the agreed beacon value");
        // The freshness nonce is usable for a replay-proof challenge.
        assert_eq!(
            state.nonce_for(b"attest:subject"),
            Some(r0.nonce_for(b"attest:subject"))
        );
    }
}
