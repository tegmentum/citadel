//! `citadel-agent` — run one mesh node as a networked process.
//!
//! Configuration is via environment variables (a demo-grade launcher):
//!
//! * `CITADEL_MESH_ID`   — mesh/trust domain (default `citadel`)
//! * `CITADEL_SEED`      — this node's identity seed, 0–255 (required)
//! * `CITADEL_ROLE`      — node role (default `worker`)
//! * `CITADEL_LISTEN`    — HTTP listen address (default `127.0.0.1:7800`)
//! * `CITADEL_TICK_MS`   — SWIM tick interval in ms (default `500`)
//! * `CITADEL_PEERS`     — JSON `[[seed, "http://host:port"], ...]` of peers
//!
//! Peer ids are derived from their seeds (the same seed-based identity the
//! mesh harness uses), so the launcher can address peers without a registry.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use citadel_agent::http::{router, HttpTransport};
use citadel_agent::{build_node, peer_id, peer_public_key, spawn_node};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mesh_id = MeshId::new(std::env::var("CITADEL_MESH_ID").unwrap_or_else(|_| "citadel".into()));
    let seed: u8 = std::env::var("CITADEL_SEED")
        .map_err(|_| anyhow::anyhow!("CITADEL_SEED is required (0-255)"))?
        .parse()?;
    let role = std::env::var("CITADEL_ROLE").unwrap_or_else(|_| "worker".into());
    let listen = std::env::var("CITADEL_LISTEN").unwrap_or_else(|_| "127.0.0.1:7800".into());
    let tick_ms: u64 = std::env::var("CITADEL_TICK_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(500);
    let peers_cfg: Vec<(u8, String)> =
        serde_json::from_str(&std::env::var("CITADEL_PEERS").unwrap_or_else(|_| "[]".into()))?;

    let epoch = 1u64;
    let config = NodeConfig {
        mesh_epoch: epoch,
        ..NodeConfig::default()
    };

    // Resolve peers' ids + keys from their seeds.
    let peers: Vec<(NodeId, _)> = peers_cfg
        .iter()
        .map(|(s, _)| (peer_id(&mesh_id, epoch, *s), peer_public_key(*s)))
        .collect();
    let url_map: HashMap<NodeId, String> = peers_cfg
        .iter()
        .map(|(s, url)| (peer_id(&mesh_id, epoch, *s), url.clone()))
        .collect();

    let (node, id) = build_node(&mesh_id, seed, &role, config, &peers);
    tracing::info!("citadel-agent {} (seed {seed}) listening on {listen}", id);

    let transport = Arc::new(HttpTransport::new(url_map));
    let handle = spawn_node(node, transport, Duration::from_millis(tick_ms));

    let app = router(handle);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
