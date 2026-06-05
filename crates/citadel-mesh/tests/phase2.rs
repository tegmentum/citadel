//! Phase 2 acceptance (design §19, Phase 2 — Gossip Membership):
//!
//! * a sizable mesh converges on membership;
//! * a batch of node failures is detected `Alive → Suspect → Faulty` across
//!   *all* survivors (gossip spreads the suspicion, not just direct probes);
//! * survivors are never falsely accused (no compromise from a partition);
//! * a restarted node refutes the stale suspicion with a higher incarnation.
//!
//! Witnessing is disabled here so the test isolates the SWIM failure
//! detector (trust-by-witness is exercised in the Phase 3 tests).

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::LivenessState;
use citadel_mesh::NodeId;

const N: u8 = 30;

fn liveness_only_mesh() -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 0,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=N).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

#[test]
fn large_mesh_converges_and_detects_batch_failure() {
    let (mut mesh, ids) = liveness_only_mesh();
    mesh.run(5);

    // Everyone sees everyone alive to start.
    let v = mesh.fleet_view(ids[0]);
    assert_eq!(v.total, N as usize);
    assert_eq!(v.alive, N as usize);

    // Kill a batch (~1/6 of the cluster).
    let dead: Vec<NodeId> = ids.iter().copied().step_by(6).collect();
    for &d in &dead {
        mesh.kill(d);
    }
    mesh.run(60);

    // Every survivor converges: the dead are Faulty, the living are Alive.
    let survivors: Vec<NodeId> = ids.iter().copied().filter(|i| !dead.contains(i)).collect();
    for &observer in &survivors {
        for &d in &dead {
            assert_eq!(
                mesh.liveness_of(observer, d),
                Some(LivenessState::Faulty),
                "{observer} should see dead {d} faulty"
            );
        }
        for &s in &survivors {
            assert_eq!(
                mesh.liveness_of(observer, s),
                Some(LivenessState::Alive),
                "{observer} should not falsely accuse live {s}"
            );
        }
    }
}

#[test]
fn restarted_node_refutes_at_scale() {
    let (mut mesh, ids) = liveness_only_mesh();
    mesh.run(5);

    let victim = ids[7];
    mesh.kill(victim);
    mesh.run(60);
    assert_eq!(mesh.liveness_of(ids[0], victim), Some(LivenessState::Faulty));

    // It comes back and clears the stale suspicion mesh-wide.
    mesh.revive(victim);
    mesh.run(60);
    for &observer in &ids {
        if observer == victim {
            continue;
        }
        assert_eq!(
            mesh.liveness_of(observer, victim),
            Some(LivenessState::Alive),
            "{observer} should re-admit the restarted victim"
        );
    }
    assert!(mesh.node(victim).membership().my_incarnation() >= 1);
}
