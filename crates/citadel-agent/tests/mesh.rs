//! Item 1 acceptance: real async agents (each a `citadel-mesh` node in a
//! tokio actor) form a mesh and run the SWIM failure detector over a
//! pluggable transport — here the in-process [`ChannelSwitchboard`], so the
//! test is socket-free and reliable. The HTTP transport is the same `Node`
//! logic behind a different `Transport` impl (smoke-tested separately).

use std::sync::Arc;
use std::time::{Duration, Instant};

use citadel_agent::{
    build_node, peer_id, peer_public_key, spawn_node, AgentHandle, ChannelSwitchboard,
};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

const EPOCH: u64 = 1;
const TICK: Duration = Duration::from_millis(15);

fn cfg() -> NodeConfig {
    NodeConfig {
        mesh_epoch: EPOCH,
        // Liveness-only for this test (no attestation traffic), fast probes.
        witness_count: 0,
        probe_interval: 1,
        suspicion_timeout: 3,
        ..NodeConfig::default()
    }
}

/// Spawn `seeds` agents over a shared in-process switchboard, each seeded
/// with the full peer roster.
fn spawn_mesh(mesh_id: &MeshId, seeds: &[u8]) -> (ChannelSwitchboard, Vec<AgentHandle>) {
    let switchboard = ChannelSwitchboard::new();
    let roster: Vec<(NodeId, _)> = seeds
        .iter()
        .map(|s| (peer_id(mesh_id, EPOCH, *s), peer_public_key(*s)))
        .collect();
    let mut handles = Vec::new();
    for &s in seeds {
        let (node, _id) = build_node(mesh_id, s, "worker", cfg(), &roster);
        let handle = spawn_node(node, Arc::new(switchboard.clone()), TICK);
        switchboard.register(&handle);
        handles.push(handle);
    }
    (switchboard, handles)
}

/// Poll `cond` against every agent's status until true or the deadline.
async fn wait_until(
    handles: &[AgentHandle],
    timeout: Duration,
    mut cond: impl FnMut(&AgentHandle, &[citadel_agent::MemberRow]) -> bool,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let mut all = true;
        for h in handles {
            let rows = h.status().await;
            if !cond(h, &rows) {
                all = false;
                break;
            }
        }
        if all {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(TICK).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_form_a_mesh_and_detect_failure_over_the_transport() {
    let mesh_id = MeshId::new("agent-test-mesh");
    let seeds = [1u8, 2, 3];
    let (_sb, handles) = spawn_mesh(&mesh_id, &seeds);

    // Every agent sees all three members alive.
    let converged = wait_until(&handles, Duration::from_secs(5), |_h, rows| {
        rows.len() == 3 && rows.iter().filter(|r| r.liveness == "alive").count() == 3
    })
    .await;
    assert!(
        converged,
        "the three agents should converge on a live membership"
    );

    // Stop the third agent: it no longer gossips or responds.
    let dead = handles[2].id();
    handles[2].shutdown();

    // The two survivors drive the dead node Alive → … → Faulty.
    let survivors = [handles[0].clone(), handles[1].clone()];
    let detected = wait_until(&survivors, Duration::from_secs(8), |_h, rows| {
        rows.iter()
            .any(|r| r.node_id == dead.to_hex() && r.liveness == "faulty")
    })
    .await;
    assert!(
        detected,
        "survivors should detect the stopped agent as faulty"
    );

    // And they still see each other alive (a partition is not a compromise).
    let still_alive = wait_until(&survivors, Duration::from_secs(2), |h, rows| {
        let me = h.id().to_hex();
        rows.iter()
            .filter(|r| r.node_id != dead.to_hex())
            .all(|r| r.liveness == "alive" || r.node_id == me)
    })
    .await;
    assert!(still_alive, "survivors must not falsely accuse each other");
}
