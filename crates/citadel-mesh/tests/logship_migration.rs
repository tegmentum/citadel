//! Self-describing placement + policy migration: each sealed window records
//! the holder-selection policy it was placed under, so flipping the mesh's
//! placement policy is safe — old windows keep finding their holders — and a
//! rate-limited migration bleeds them over to the new policy a few at a time
//! without ever dropping a window below its reconstruction threshold.

use citadel_mesh::evidence::payload_hash;
use citadel_mesh::harness::Mesh;
use citadel_mesh::logship::PlacementPolicy;
use citadel_mesh::node::{NodeConfig, WindowPlacement};
use citadel_mesh::NodeId;

/// 3 data + 2 parity (5 shards), erasure replication on, LtHash advertising
/// off so the only movement is the durable-evidence path under test.
fn cfg() -> NodeConfig {
    NodeConfig {
        witness_count: 0,
        log_window_size: 8,
        log_advertise_interval: 0,
        evidence_replication: true,
        evidence_data_shards: 3,
        evidence_parity_shards: 2,
        evidence_offbox: false, // start under FullRoster
        ..NodeConfig::default()
    }
}

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=n).map(|s| mesh.add_node(s, "worker", cfg())).collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

/// Seal three windows (24 events over a window of 8) and ship them.
fn seal_three_windows(mesh: &mut Mesh, origin: NodeId) {
    for i in 0..24u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("event-{i}").as_bytes()));
    }
    mesh.run(10);
}

fn placement(mesh: &Mesh, origin: NodeId, window: u64) -> WindowPlacement {
    mesh.node(origin)
        .window_placement(1, window)
        .expect("window shipped")
}

fn offbox_count(mesh: &Mesh, origin: NodeId) -> usize {
    (0..3)
        .filter(|&w| placement(mesh, origin, w).policy == PlacementPolicy::OffBox)
        .count()
}

#[test]
fn flipping_the_policy_leaves_old_windows_reconstructable() {
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    seal_three_windows(&mut mesh, origin);

    // All three windows were placed under the original FullRoster policy.
    for w in 0..3 {
        assert_eq!(
            placement(&mesh, origin, w).policy,
            PlacementPolicy::FullRoster
        );
    }

    // Flip the target policy to OffBox but with migration DISABLED (rate 0):
    // existing windows keep their recorded FullRoster placement.
    mesh.set_evidence_placement_all(true, 2, 0);
    mesh.run(5);
    assert_eq!(
        offbox_count(&mesh, origin),
        0,
        "no migration → policies unchanged"
    );

    // A window's self-describing handle still points at its FullRoster holders
    // even though the mesh's *current* policy is now OffBox — and those two
    // holder sets genuinely differ (so guessing from current config would miss).
    let p = placement(&mesh, origin, 1);
    let full_holders = mesh.node(origin).fragment_holders(&p);
    let offbox_view = WindowPlacement {
        policy: PlacementPolicy::OffBox,
        ..p
    };
    let offbox_holders = mesh.node(origin).fragment_holders(&offbox_view);
    assert_ne!(
        full_holders, offbox_holders,
        "the two policies pick different holders"
    );

    // Reconstruct the old window via its recorded placement: kill two of its
    // (FullRoster) holders, a third survivor rebuilds it.
    let recoverer = full_holders[0];
    for &dead in full_holders.iter().skip(1).take(2) {
        mesh.kill(dead);
    }
    mesh.node_mut(recoverer).request_reconstruction(&p);
    mesh.run(10);
    assert!(
        mesh.node(recoverer).has_recovered(p.record_id),
        "the self-describing FullRoster placement still locates the holders"
    );
}

#[test]
fn migration_slowly_moves_windows_to_the_new_policy() {
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    seal_three_windows(&mut mesh, origin);

    // Flip to OffBox, migrating at most one window at a time.
    mesh.set_evidence_placement_all(true, 2, 1);

    // It is gradual: a couple of steps move some — but not all — windows.
    mesh.run(2);
    let partial = offbox_count(&mesh, origin);
    assert!(
        (1..3).contains(&partial),
        "migration should be partway, got {partial} of 3"
    );

    // Given enough steps every window ends up under the new policy.
    mesh.run(8);
    assert_eq!(offbox_count(&mesh, origin), 3, "all windows migrated");

    // Under OffBox the subject is never one of its own holders, and any shard
    // it used to hold of its own windows has been dropped.
    for w in 0..3 {
        let p = placement(&mesh, origin, w);
        let holders = mesh.node(origin).fragment_holders(&p);
        assert!(
            !holders.contains(&origin),
            "subject excluded from window {w}"
        );
        assert_eq!(
            mesh.node(origin).held_fragment_count(p.record_id),
            0,
            "subject dropped its own shard of window {w}"
        );
    }

    // Evidence survived the move: a migrated window still reconstructs from its
    // new holders after losing `parity` (2) of them.
    let p = placement(&mesh, origin, 0);
    let holders = mesh.node(origin).fragment_holders(&p);
    let recoverer = holders[0];
    for &dead in holders.iter().skip(1).take(2) {
        mesh.kill(dead);
    }
    mesh.node_mut(recoverer).request_reconstruction(&p);
    mesh.run(10);
    assert!(
        mesh.node(recoverer).has_recovered(p.record_id),
        "migrated window reconstructs from its new holders"
    );
}

#[test]
fn offbox_paired_with_a_parity_bump_raises_fault_tolerance() {
    // Pairing OffBox with a parity bump offsets the holder candidate the
    // subject loses, and migration re-ships every window under the new, more
    // redundant scheme. Use an 8-node mesh so OffBox still yields distinct
    // holders at the higher shard count.
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=8).map(|s| mesh.add_node(s, "worker", cfg())).collect();
    mesh.wire_full_membership();
    let origin = ids[0];
    seal_three_windows(&mut mesh, origin);

    // Baseline: FullRoster, 5 shards (3 data + 2 parity).
    assert_eq!(placement(&mesh, origin, 0).holder_count, 5);

    // Flip to OffBox AND bump parity 2 → 4 (total 7), migrating one at a time.
    mesh.set_evidence_placement_all(true, 4, 1);
    mesh.run(12);

    // Every window is now OffBox with the new 7-shard scheme.
    for w in 0..3 {
        let p = placement(&mesh, origin, w);
        assert_eq!(p.policy, PlacementPolicy::OffBox);
        assert_eq!(p.holder_count, 7, "data 3 + parity 4");
        let holders = mesh.node(origin).fragment_holders(&p);
        assert_eq!(
            holders.len(),
            7,
            "7 distinct holders among the 7 non-subject peers"
        );
        assert!(!holders.contains(&origin));
    }

    // The bumped parity now tolerates losing 4 holders (vs 2 before): kill 4 of
    // the 7, reconstruct from the remaining 3 = the data-shard threshold.
    let p = placement(&mesh, origin, 0);
    let holders = mesh.node(origin).fragment_holders(&p);
    let recoverer = holders[0];
    for &dead in holders.iter().skip(1).take(4) {
        mesh.kill(dead);
    }
    mesh.node_mut(recoverer).request_reconstruction(&p);
    mesh.run(10);
    assert!(
        mesh.node(recoverer).has_recovered(p.record_id),
        "the bumped parity survives 4 holder losses"
    );
}

#[test]
fn migration_never_drops_a_window_below_threshold() {
    // At every point during migration the window is reconstructable: we step
    // one at a time and, at each step, rebuild window 0 from a clean recoverer.
    let (mut mesh, ids) = mesh_of(6);
    let origin = ids[0];
    seal_three_windows(&mut mesh, origin);
    mesh.set_evidence_placement_all(true, 2, 1);

    for _ in 0..8 {
        mesh.run(1);
        // Use the window's *current* committed placement to find its holders.
        let p = placement(&mesh, origin, 0);
        let holders = mesh.node(origin).fragment_holders(&p);
        // A holder that is not the origin acts as recoverer; it should always
        // be able to gather a threshold of shards.
        let recoverer = *holders
            .iter()
            .find(|h| **h != origin)
            .unwrap_or(&holders[0]);
        mesh.node_mut(recoverer).request_reconstruction(&p);
        mesh.run(3);
        assert!(
            mesh.node(recoverer).has_recovered(p.record_id),
            "window 0 stayed reconstructable mid-migration"
        );
    }
}
