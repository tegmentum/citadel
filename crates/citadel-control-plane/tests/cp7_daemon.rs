//! CP7 combined daemon: a live observer agent (a real `citadel-mesh` node in a
//! tokio actor, over the in-process switchboard transport) feeds verified
//! verdicts into a ControlPlane via the daemon's ingest path, and the fleet view
//! converges to the mesh's actual trust — no sockets, but the real actor +
//! observer_feed + ingest_observer_feed path.
#![cfg(feature = "daemon")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use citadel_agent::{build_node, peer_id, peer_public_key, spawn_node, ChannelSwitchboard};
use citadel_control_plane::daemon::ingest_once;
use citadel_control_plane::{ControlPlane, MemStore};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

const EPOCH: u64 = 1;
const TICK: Duration = Duration::from_millis(15);

#[tokio::test]
async fn the_daemon_ingests_a_live_observer_agents_feed() {
    let mesh_id = MeshId::new("daemon-test");
    let worker_seeds = [1u8, 2, 3, 4, 5];
    let obs_seed = 9u8;
    let all: Vec<u8> = worker_seeds
        .iter()
        .copied()
        .chain(std::iter::once(obs_seed))
        .collect();
    let roster: Vec<(NodeId, _)> = all
        .iter()
        .map(|s| (peer_id(&mesh_id, EPOCH, *s), peer_public_key(*s)))
        .collect();

    let sb = ChannelSwitchboard::new();
    let wcfg = NodeConfig {
        mesh_epoch: EPOCH,
        witness_count: 3,
        attestation_interval: 2,
        ..NodeConfig::default()
    };
    let mut workers = Vec::new();
    for &s in &worker_seeds {
        let (node, id) = build_node(&mesh_id, s, "worker", wcfg.clone(), &roster);
        let h = spawn_node(node, Arc::new(sb.clone()), TICK);
        sb.register(&h);
        workers.push(id);
    }
    // The control plane's observer node: non-voting, in the same mesh.
    let ocfg = NodeConfig {
        observer: true,
        ..wcfg.clone()
    };
    let (onode, _oid) = build_node(&mesh_id, obs_seed, "control-plane", ocfg, &roster);
    let observer = spawn_node(onode, Arc::new(sb.clone()), TICK);
    sb.register(&observer);

    let cp = Arc::new(Mutex::new(ControlPlane::new(MemStore::new())));

    // Run daemon ingest cycles until the CP sees every worker trusted.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut tick = 0u64;
    loop {
        tick += 1;
        ingest_once(&cp, &observer, tick).await;
        let trusted = {
            let g = cp.lock().unwrap();
            workers
                .iter()
                .filter(|w| {
                    g.node_view(w)
                        .map(|v| v.trust == "trusted")
                        .unwrap_or(false)
                })
                .count()
        };
        if trusted == workers.len() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "daemon CP reached only {trusted}/{} trusted",
            workers.len()
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let g = cp.lock().unwrap();
    let h = g.fleet_health();
    assert_eq!(
        h.total,
        workers.len(),
        "the observer is excluded from the fleet"
    );
    assert_eq!(
        h.trusted,
        workers.len(),
        "the daemon's CP matches the mesh's trust"
    );
}
