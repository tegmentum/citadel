//! MSS6b live transport over the async agent runtime: holder agents run the two
//! FROST signing rounds over the agent's AppRelay channel (in-process
//! switchboard) and the coordinator aggregates a valid group signature.

use std::sync::Arc;
use std::time::Duration;

use citadel_agent::{
    build_node, peer_id, peer_public_key, spawn_node, AgentHandle, ChannelSwitchboard,
};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;
use citadel_mss::session::{self, Round1Message, Round2Message};
use citadel_mss::tsig;

const EPOCH: u64 = 1;
const TICK: Duration = Duration::from_millis(15);
const T1: [u8; 32] = [0xF1; 32];
const T2: [u8; 32] = [0xF2; 32];

#[tokio::test]
async fn holder_agents_threshold_sign_over_apprelay() {
    let mesh_id = MeshId::new("mss-sign");
    let seeds = [1u8, 2, 3, 4, 5];
    let roster: Vec<(NodeId, _)> = seeds
        .iter()
        .map(|s| (peer_id(&mesh_id, EPOCH, *s), peer_public_key(*s)))
        .collect();
    let cfg = NodeConfig {
        mesh_epoch: EPOCH,
        witness_count: 0,
        probe_interval: 1,
        ..NodeConfig::default()
    };

    let sb = ChannelSwitchboard::new();
    let mut agents: Vec<AgentHandle> = Vec::new();
    for &s in &seeds {
        let (node, _) = build_node(&mesh_id, s, "worker", cfg.clone(), &roster);
        let h = spawn_node(node, Arc::new(sb.clone()), TICK);
        sb.register(&h);
        agents.push(h);
    }

    // A 3-of-5 FROST signing key; the test holds one package per holder.
    let (public, packages) = tsig::keygen(3, 5).unwrap();
    let message = b"issue-cert: cn=workload-7";
    let signers = 0..3usize;

    // Round 1: each signer commits and broadcasts over AppRelay.
    let mut nonces = Vec::new();
    let mut own_r1 = Vec::new();
    for i in signers.clone() {
        let (n, m) = session::round1(&packages[i]);
        nonces.push(n);
        agents[i].broadcast_app(T1, m.to_bytes()).await;
        own_r1.push(m);
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // let gossip deliver

    // Round 2: each signer assembles round-1 (peers' + own), builds the package,
    // signs, and broadcasts its share.
    let mut own_r2 = Vec::new();
    let mut packages_built = Vec::new();
    for (idx, i) in signers.clone().enumerate() {
        let mut r1: Vec<Round1Message> = agents[i]
            .drain_app(T1)
            .await
            .iter()
            .map(|b| Round1Message::from_bytes(b).unwrap())
            .collect();
        r1.push(own_r1[idx].clone());
        let sp = session::signing_package(&r1, message);
        let r2 = session::round2(&sp, &nonces[idx], &packages[i]).unwrap();
        agents[i].broadcast_app(T2, r2.to_bytes()).await;
        own_r2.push(r2);
        packages_built.push(sp);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The coordinator aggregates the shares from gossip + its own.
    let mut r2: Vec<Round2Message> = agents[0]
        .drain_app(T2)
        .await
        .iter()
        .map(|b| Round2Message::from_bytes(b).unwrap())
        .collect();
    r2.push(own_r2[0].clone());

    let sig = session::finish(&packages_built[0], &r2, &public).unwrap();
    assert!(
        tsig::verify(&public, message, &sig),
        "agents produced a valid threshold signature over gossip"
    );

    for a in &agents {
        a.shutdown();
    }
}
