//! # citadel-spire-plugin — SPIRE NodeAttestor over mesh trust (SP2)
//!
//! A SPIRE **server NodeAttestor** plugin: when SPIRE attests an agent, this
//! plugin consults Citadel's mesh trust and only returns an agent identity +
//! `citadel:` selectors if the node is currently **Verified**; otherwise it
//! denies attestation, so SPIRE will not issue (or, on re-attestation, renew) the
//! agent's SVID. This is the gRPC shell over the SP1 decision core
//! (`citadel-spiffe`); the upstream SPIRE plugin-SDK protos are vendored under
//! `proto/` and compiled with a hermetic protoc.
//!
//! The external wiring (go-plugin handshake so a live SPIRE server can launch
//! this binary) is in `main.rs`; see `README.md` for the Docker harness.

// tonic's Status Err is intentionally large; the vendored protos' doc comments
// use deeper list indentation than clippy prefers — both are noise here.
#![allow(
    clippy::result_large_err,
    clippy::doc_overindented_list_items,
    clippy::doc_lazy_continuation
)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use citadel_mesh::NodeId;
use citadel_spiffe::{IssuanceDecision, NodeTrustView, SpiffeId, TrustDomain};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

pub mod agent;
pub mod mtls;
pub mod runtime;

/// The compiled proto file-descriptor set, for gRPC reflection (SPIRE discovers
/// a plugin's services via reflection).
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/citadel_spire_descriptor.bin"));

/// The go-plugin handshake magic cookie for a SPIRE NodeAttestor: the env var key
/// and value are both the plugin type name (`internal.ServerHandshakeConfig`).
pub const MAGIC_COOKIE_KEY: &str = "NodeAttestor";
pub const MAGIC_COOKIE_VALUE: &str = "NodeAttestor";

/// Generated upstream SPIRE plugin-SDK code.
pub mod nodeattestor {
    tonic::include_proto!("spire.plugin.server.nodeattestor.v1");
}
pub mod config {
    tonic::include_proto!("spire.service.common.config.v1");
}

use config::config_server::{Config, ConfigServer};
use config::{ConfigureRequest, ConfigureResponse, ValidateRequest, ValidateResponse};
use nodeattestor::node_attestor_server::{NodeAttestor, NodeAttestorServer};
use nodeattestor::{
    attest_request, attest_response, AgentAttributes, AttestRequest, AttestResponse,
};

/// The trust + selector source the plugin consults — implemented by the control
/// plane (`spiffe_node_view`). Kept as a trait so the plugin is decoupled and
/// testable with a mock.
pub trait TrustView: Send + Sync + 'static {
    fn node_trust_view(&self, node: &NodeId) -> NodeTrustView;
}

/// The attestation payload a Citadel agent presents. A production attestor would
/// carry a fresh TPM quote here (validated against the node's AK); the mesh's
/// continuous trust is the authority for issuance, so the scaffold carries the
/// node id and notes the quote-verification seam.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AttestationPayload {
    pub node_id: String,
}

/// The plugin state shared by both gRPC services.
pub struct CitadelPlugin<T: TrustView> {
    trust: T,
    trust_domain: Mutex<TrustDomain>,
}

impl<T: TrustView> CitadelPlugin<T> {
    pub fn new(trust: T) -> Arc<Self> {
        Arc::new(CitadelPlugin {
            trust,
            trust_domain: Mutex::new(TrustDomain::default()),
        })
    }

    fn domain(&self) -> TrustDomain {
        self.trust_domain.lock().unwrap().clone()
    }
}

type AttestStream = Pin<Box<dyn Stream<Item = Result<AttestResponse, Status>> + Send>>;

#[tonic::async_trait]
impl<T: TrustView> NodeAttestor for Arc<CitadelPlugin<T>> {
    type AttestStream = AttestStream;

    async fn attest(
        &self,
        request: Request<Streaming<AttestRequest>>,
    ) -> Result<Response<Self::AttestStream>, Status> {
        let mut stream = request.into_inner();
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("attest stream closed before payload"))?;
        let payload = match first.request {
            Some(attest_request::Request::Payload(p)) => p,
            _ => {
                return Err(Status::invalid_argument(
                    "first message must carry the payload",
                ))
            }
        };
        let parsed: AttestationPayload = serde_json::from_slice(&payload)
            .map_err(|e| Status::invalid_argument(format!("malformed payload: {e}")))?;
        let node = NodeId(parse_hex32(&parsed.node_id)?);

        // The mesh's continuous trust decides issuance (SP2/SP3).
        let view = self.trust.node_trust_view(&node);
        let decision = IssuanceDecision::for_level(view.trust_level);
        if !decision.may_issue_new() {
            return Err(Status::permission_denied(format!(
                "mesh trust level is '{}'; SPIRE attestation denied (issuance requires 'verified')",
                view.trust_level.as_str()
            )));
        }

        let attrs = AgentAttributes {
            spiffe_id: SpiffeId::node(&self.domain(), &node).to_string(),
            selector_values: view.selectors(),
            can_reattest: true, // re-attestation re-checks trust → enforces continuity
        };
        let resp = AttestResponse {
            response: Some(attest_response::Response::AgentAttributes(attrs)),
        };
        Ok(Response::new(Box::pin(tokio_stream::once(Ok(resp)))))
    }
}

#[tonic::async_trait]
impl<T: TrustView> Config for Arc<CitadelPlugin<T>> {
    async fn configure(
        &self,
        request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        if let Some(core) = request.into_inner().core_configuration {
            if !core.trust_domain.is_empty() {
                *self.trust_domain.lock().unwrap() = TrustDomain::new(core.trust_domain);
            }
        }
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn validate(
        &self,
        _request: Request<ValidateRequest>,
    ) -> Result<Response<ValidateResponse>, Status> {
        Ok(Response::new(ValidateResponse {
            valid: true,
            notes: vec![],
        }))
    }
}

/// Build a tonic router serving both the NodeAttestor and Config services for a
/// plugin instance — used by the self-contained test and the go-plugin binary.
pub fn router<T: TrustView>(plugin: Arc<CitadelPlugin<T>>) -> tonic::transport::server::Router {
    tonic::transport::Server::builder()
        .add_service(NodeAttestorServer::new(plugin.clone()))
        .add_service(ConfigServer::new(plugin))
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Status> {
    if s.len() != 64 {
        return Err(Status::invalid_argument("node id must be 32 hex bytes"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| Status::invalid_argument("node id is not valid hex"))?;
    }
    Ok(out)
}
