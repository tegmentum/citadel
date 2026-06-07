//! Reference-manifest distribution over the real HTTP transport (roadmap E1):
//! a signed manifest gossiped from one agent reaches the whole fleet, and a
//! manifest seeded into a single agent spreads to the rest via anti-entropy —
//! the same measured-state-transition flows the deterministic harness exercises,
//! now over sockets.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use citadel_agent::http::{router, HttpTransport};
use citadel_agent::{build_node, peer_id, peer_public_key, spawn_node, AgentHandle};
use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{ReferenceEntry, ReferenceManifest, Validity};
use citadel_mesh::{MeshKeypair, NodeId};

const EPOCH: u64 = 1;

async fn spawn_fleet(mesh_id: &MeshId, seeds: &[u8], cfg: NodeConfig) -> HashMap<u8, AgentHandle> {
    let mut listeners = Vec::new();
    let mut urls: HashMap<u8, String> = HashMap::new();
    for &s in seeds {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.insert(s, format!("http://{}", l.local_addr().unwrap()));
        listeners.push((s, l));
    }
    let roster: Vec<(NodeId, _)> = seeds
        .iter()
        .map(|s| (peer_id(mesh_id, EPOCH, *s), peer_public_key(*s)))
        .collect();

    let mut handles: HashMap<u8, AgentHandle> = HashMap::new();
    for (s, listener) in listeners {
        let url_map: HashMap<NodeId, String> = seeds
            .iter()
            .filter(|p| **p != s)
            .map(|p| (peer_id(mesh_id, EPOCH, *p), urls[p].clone()))
            .collect();
        let (node, _id) = build_node(mesh_id, s, "worker", cfg.clone(), &roster);
        let handle = spawn_node(
            node,
            Arc::new(HttpTransport::new(url_map)),
            Duration::from_millis(40),
        );
        let app = router(handle.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        handles.insert(s, handle);
    }
    handles
}

fn a_manifest(authority: &MeshKeypair) -> ReferenceManifest {
    ReferenceManifest::issue(
        authority,
        "prod",
        vec![ReferenceEntry::new(
            0,
            b"new-kernel-state".to_vec(),
            Validity::always(),
        )],
        vec![],
    )
}

async fn wait_all_have(handles: &HashMap<u8, AgentHandle>, seeds: &[u8], id: [u8; 32]) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut all = true;
        for s in seeds {
            if !handles[s].has_reference_manifest(id).await {
                all = false;
                break;
            }
        }
        if all {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signed_manifest_gossips_to_the_fleet_over_http() {
    let mesh_id = MeshId::new("reference-http-mesh");
    let seeds = [1u8, 2, 3];
    let cfg = NodeConfig {
        mesh_epoch: EPOCH,
        witness_count: 0,
        probe_interval: 1,
        ..NodeConfig::default()
    };
    let handles = spawn_fleet(&mesh_id, &seeds, cfg).await;

    let authority = MeshKeypair::from_seed([200u8; 32]);
    for s in &seeds {
        handles[s]
            .set_reference_authorities(TrustAnchors::with(authority.public()))
            .await;
    }
    let manifest = a_manifest(&authority);
    let id = manifest.content_id();

    // One agent broadcasts it; all converge.
    handles[&1].broadcast_reference_manifest(manifest).await;
    assert!(
        wait_all_have(&handles, &seeds, id).await,
        "a broadcast signed manifest should reach every agent over HTTP"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anti_entropy_spreads_a_seeded_manifest_over_http() {
    let mesh_id = MeshId::new("reference-ae-http-mesh");
    let seeds = [1u8, 2, 3];
    let cfg = NodeConfig {
        mesh_epoch: EPOCH,
        witness_count: 0,
        probe_interval: 1,
        reference_advertise_interval: 1, // advertise adopted-manifest ids
        ..NodeConfig::default()
    };
    let handles = spawn_fleet(&mesh_id, &seeds, cfg).await;

    let authority = MeshKeypair::from_seed([200u8; 32]);
    for s in &seeds {
        handles[s]
            .set_reference_authorities(TrustAnchors::with(authority.public()))
            .await;
    }
    let manifest = a_manifest(&authority);
    let id = manifest.content_id();

    // Seed only ONE agent (adopt-only, no broadcast). The others must pull it
    // via the ReferenceDigest anti-entropy advertisement.
    handles[&2].apply_reference_manifest(manifest).await;
    assert!(handles[&2].has_reference_manifest(id).await);
    assert!(!handles[&1].has_reference_manifest(id).await);

    assert!(
        wait_all_have(&handles, &seeds, id).await,
        "anti-entropy should spread a seeded manifest to the fleet over HTTP"
    );
}
