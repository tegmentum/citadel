//! The **agent-side** SPIRE NodeAttestor (the attestation pair's other half): it
//! produces the attestation payload the server plugin verifies. For Citadel the
//! payload is the node's id (a production attestor would carry a fresh TPM quote);
//! the mesh's continuous trust is the issuance authority.

use std::pin::Pin;
use std::sync::Mutex;

use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

/// Generated agent-side proto.
pub mod proto {
    tonic::include_proto!("spire.plugin.agent.nodeattestor.v1");
}

use crate::config::config_server::Config;
use crate::config::{ConfigureRequest, ConfigureResponse, ValidateRequest, ValidateResponse};
use proto::node_attestor_server::NodeAttestor;
use proto::{payload_or_challenge_response, Challenge, PayloadOrChallengeResponse};

/// The agent attestor: holds this node's id (hex), emitted as the payload.
pub struct AgentAttestor {
    node_id: Mutex<String>,
}

impl AgentAttestor {
    pub fn new(node_id_hex: String) -> std::sync::Arc<Self> {
        std::sync::Arc::new(AgentAttestor {
            node_id: Mutex::new(node_id_hex),
        })
    }
}

type AidStream = Pin<Box<dyn Stream<Item = Result<PayloadOrChallengeResponse, Status>> + Send>>;

#[tonic::async_trait]
impl NodeAttestor for std::sync::Arc<AgentAttestor> {
    type AidAttestationStream = AidStream;

    async fn aid_attestation(
        &self,
        _request: Request<Streaming<Challenge>>,
    ) -> Result<Response<Self::AidAttestationStream>, Status> {
        // First (and only) message: the payload the server plugin verifies.
        let node_id = self.node_id.lock().unwrap().clone();
        let payload = serde_json::to_vec(&serde_json::json!({ "node_id": node_id }))
            .map_err(|e| Status::internal(format!("payload: {e}")))?;
        let msg = PayloadOrChallengeResponse {
            data: Some(payload_or_challenge_response::Data::Payload(payload)),
        };
        Ok(Response::new(Box::pin(tokio_stream::once(Ok(msg)))))
    }
}

#[tonic::async_trait]
impl Config for std::sync::Arc<AgentAttestor> {
    async fn configure(
        &self,
        _request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
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
