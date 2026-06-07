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

    /// A transport whose reqwest client is already built — used to inject the
    /// mutual-TLS client from [`mtls_client`] (peer URLs are then `https://…`).
    pub fn with_client(peers: HashMap<NodeId, String>, client: reqwest::Client) -> Self {
        HttpTransport { peers, client }
    }
}

/// Build a reqwest client whose TLS identity is the TPM-held key (E2): it
/// presents `identity`'s certificate and accepts a server only if its cert is
/// one of `peer_certs` (the mesh roster) — mutual TLS with certificate pinning,
/// no CA. The private key never leaves the TPM.
pub fn mtls_client(
    identity: &tpm_tls::TpmTlsIdentity,
    peer_certs: Vec<tpm_tls::CertificateDer<'static>>,
) -> anyhow::Result<reqwest::Client> {
    let tls = identity.client_config(&peer_certs)?;
    Ok(reqwest::Client::builder().use_preconfigured_tls(tls).build()?)
}

/// Serve `app` over mutual TLS (E2): present `identity`'s TPM-held cert and
/// accept a client only if its cert is one of `peer_certs`.
pub async fn serve_mtls(
    app: Router,
    addr: std::net::SocketAddr,
    identity: &tpm_tls::TpmTlsIdentity,
    peer_certs: Vec<tpm_tls::CertificateDer<'static>>,
) -> anyhow::Result<()> {
    let server_config = identity.server_config(&peer_certs)?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(server_config));
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await?;
    Ok(())
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
