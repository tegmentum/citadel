//! Bounded-fan-out durable evidence wired into the live mesh: a sealed log
//! window is erasure-coded and scattered to a small set of HRW-assigned
//! holders — *not* full-replicated to every peer — survives the loss of up to
//! `parity` holders, and is reconstructable over the network from the
//! survivors. Composes logship sealing with erasure + holder assignment
//! (Phase 4) under the `evidence_replication` path.

use citadel_mesh::erasure::ErasureScheme;
use citadel_mesh::evidence::payload_hash;
use citadel_mesh::harness::Mesh;
use citadel_mesh::logship::encode_records;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

/// data=3, parity=2 → 5 shards, reconstruct from any 3, tolerate losing 2.
fn erasure_cfg() -> NodeConfig {
    NodeConfig {
        // Isolate the erasure path: no attestation traffic, and the legacy
        // LtHash full-replication advertising turned OFF so the only thing
        // moving the window is the erasure shipping under test.
        witness_count: 0,
        log_window_size: 8,
        log_advertise_interval: 0,
        evidence_replication: true,
        evidence_data_shards: 3,
        evidence_parity_shards: 2,
        ..NodeConfig::default()
    }
}

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", erasure_cfg()))
        .collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

/// Seal window 0 on `origin` (12 events over a window of 8) and let the mesh
/// ship the shards. Returns the window's record id.
fn seal_and_ship(mesh: &mut Mesh, origin: NodeId) -> [u8; 32] {
    for i in 0..12u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("event-{i}").as_bytes()));
    }
    mesh.run(10);
    mesh.node(origin)
        .shipped_record_id(1, 0)
        .expect("window 0 should have been sealed and shipped")
}

#[test]
fn a_sealed_window_ships_to_bounded_holders_not_every_peer() {
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    let record_id = seal_and_ship(&mut mesh, origin);

    // The window scattered to exactly `total` (= 5) distinct holders, chosen
    // by HRW — a bounded set, not all 6 peers.
    let holders = mesh.node(origin).fragment_holders(record_id);
    assert_eq!(holders.len(), 5, "5-shard scheme → 5 holders");

    // Every assigned holder stores a shard; the one non-holder stores none and
    // received no full replica either (we did not ship to everyone).
    for &id in &ids {
        let held = mesh.node(id).held_fragment_count(record_id);
        if holders.contains(&id) {
            assert!(held >= 1, "assigned holder {id} should store a shard");
        } else {
            assert_eq!(held, 0, "non-holder {id} should store nothing");
            assert!(
                mesh.node(id).replica_root(origin).is_none(),
                "non-holder {id} must not hold a full replica"
            );
        }
    }

    // Holders acknowledged: durability is at/above 1.0 (>= threshold shards).
    let durability = mesh.node(origin).window_durability(1, 0).unwrap();
    assert!(durability >= 1.0, "all shards acknowledged: {durability}");
}

#[test]
fn evidence_survives_losing_parity_holders_and_rebuilds_over_the_network() {
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    let record_id = seal_and_ship(&mut mesh, origin);

    let holders = mesh.node(origin).fragment_holders(record_id);
    // A recoverer that is a holder (so it has one shard already), and two
    // *other* holders to destroy — losing `parity` = 2 of the 5 shards.
    let recoverer = holders[0];
    let to_kill: Vec<NodeId> = holders.iter().copied().filter(|h| *h != recoverer).take(2).collect();
    assert_eq!(to_kill.len(), 2);
    for &dead in &to_kill {
        mesh.kill(dead);
    }

    // The recoverer rebuilds the window from the 3 surviving shards.
    mesh.node_mut(recoverer).request_reconstruction(record_id);
    mesh.run(10);
    assert!(
        mesh.node(recoverer).has_recovered(record_id),
        "3 of 5 surviving shards must reconstruct the window"
    );

    // The rebuilt records match what the origin actually sealed.
    let mut origin_log = citadel_mesh::logship::EventLog::new(8);
    for i in 0..8u64 {
        origin_log.append(citadel_mesh::logship::EventRecord {
            node_id: origin,
            boot_id: 1,
            sequence: i,
            payload_hash: payload_hash(format!("event-{i}").as_bytes()),
        });
    }
    assert_eq!(
        mesh.node(recoverer).replica_root(origin),
        Some(origin_log.root()),
        "reconstructed replica equals the origin's sealed window"
    );
}

#[test]
fn losing_more_than_parity_holders_makes_a_window_unrecoverable() {
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    let record_id = seal_and_ship(&mut mesh, origin);

    let holders = mesh.node(origin).fragment_holders(record_id);
    // The non-holder is a clean recoverer (holds no shard of its own).
    let recoverer = *ids.iter().find(|id| !holders.contains(id)).expect("one non-holder");
    // Destroy 3 of 5 holders — only 2 shards remain, below the threshold of 3.
    for &dead in holders.iter().take(3) {
        mesh.kill(dead);
    }

    mesh.node_mut(recoverer).request_reconstruction(record_id);
    mesh.run(10);
    assert!(
        !mesh.node(recoverer).has_recovered(record_id),
        "2 of 5 surviving shards are below the reconstruction threshold"
    );
}

#[test]
fn the_record_id_commits_to_the_sealed_window_contents() {
    // Independent check that the on-wire record id is exactly the content hash
    // of the encoded window — so a holder/recoverer can verify what it stores.
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    let record_id = seal_and_ship(&mut mesh, origin);

    let mut log = citadel_mesh::logship::EventLog::new(8);
    for i in 0..8u64 {
        log.append(citadel_mesh::logship::EventRecord {
            node_id: origin,
            boot_id: 1,
            sequence: i,
            payload_hash: payload_hash(format!("event-{i}").as_bytes()),
        });
    }
    let expected = payload_hash(&encode_records(&log.records_in(0, 8)));
    assert_eq!(record_id, expected);

    // And the scheme really is the 5-shard one we configured.
    let scheme = ErasureScheme::new(3, 2).unwrap();
    assert_eq!(scheme.total(), 5);
}
