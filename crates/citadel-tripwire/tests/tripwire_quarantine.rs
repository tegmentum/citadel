//! TW2 live: a sealed-decoy trip gossips over AppRelay and drives mesh-wide
//! quarantine of the attributed node through the existing M2 flow.

use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::quarantine::QuarantineScope;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;
use citadel_tripwire::{triage, TripClass, TripEvent, Tripwire, TRIP_TOPIC};

#[test]
fn a_sealed_decoy_trip_drives_mesh_quarantine() {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 4,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(12);

    let observer = workers[0];
    let observer_kp = MeshKeypair::from_seed([1; 32]); // workers[0]'s mesh key
    let attacker = workers[5];

    // The attacker is compromised — its measured state trips the decoy *and* its
    // witnesses independently see it as Suspicious (so the quorum will agree to
    // contain it; one node can't quarantine a healthy peer).
    mesh.measured_state_change(attacker, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(
        mesh.trust_of(observer, attacker),
        Some(TrustState::Suspicious)
    );

    let tw = Tripwire::new("db/root-password-decoy", TripClass::SealedDecoy);

    // The observer detects the attacker decrypting the sealed decoy → signs a
    // trip → gossips it.
    let trip = TripEvent::sign(&observer_kp, &tw, observer, Some(attacker), 20);
    mesh.node_mut(observer)
        .broadcast_app(TRIP_TOPIC, trip.to_bytes());
    mesh.run(6);

    // A witness drains the trip, triages it, and proposes mesh quarantine.
    let observers = [(observer, observer_kp.public())];
    let responder = workers[1];
    let trips = mesh.node_mut(responder).drain_app(TRIP_TOPIC);
    let actions = triage(&trips, &observers);
    assert_eq!(actions.len(), 1, "one high-confidence containment");
    for c in &actions {
        mesh.node_mut(responder)
            .propose_and_broadcast_quarantine(c.subject, c.scope, 26);
    }
    mesh.run(10);

    // The attacker is contained mesh-wide.
    for &w in &workers[..5] {
        assert_eq!(
            mesh.node(w).quarantine_of(attacker),
            Some(QuarantineScope::BlockWorkloadScheduling),
            "trip → quarantine enacted at every witness"
        );
    }
}
