//! HTTP transport and the agent's gossip/status endpoints.

use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use citadel_mesh::types::GossipEnvelope;
use citadel_mesh::NodeId;

use crate::{AgentHandle, MemberRow, Transport};

/// Dispatches gossip by `POST {peer}/v1/gossip`. Sends are spawned and
/// fire-and-forget: an unreachable peer simply misses the message, which the
/// failure detector treats as a missed probe.
pub struct HttpTransport {
    peers: HashMap<NodeId, String>,
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(peers: HashMap<NodeId, String>) -> Self {
        HttpTransport {
            peers,
            client: reqwest::Client::new(),
        }
    }
}

impl Transport for HttpTransport {
    fn dispatch(&self, to: NodeId, envelope: GossipEnvelope) {
        let Some(base) = self.peers.get(&to) else {
            return;
        };
        let url = format!("{base}/v1/gossip");
        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client.post(&url).json(&envelope).send().await {
                tracing::trace!("gossip dispatch to {url} failed: {e}");
            }
        });
    }
}

/// The agent's HTTP surface: accept gossip, report membership.
pub fn router(handle: AgentHandle) -> Router {
    Router::new()
        .route("/v1/gossip", post(gossip))
        .route("/v1/mesh/status", get(status))
        .with_state(handle)
}

async fn gossip(State(handle): State<AgentHandle>, Json(envelope): Json<GossipEnvelope>) -> StatusCode {
    handle.deliver(envelope).await;
    StatusCode::ACCEPTED
}

async fn status(State(handle): State<AgentHandle>) -> Json<Vec<MemberRow>> {
    Json(handle.status().await)
}
