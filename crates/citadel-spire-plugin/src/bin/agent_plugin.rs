//! Citadel **agent-side** SPIRE NodeAttestor go-plugin — the attestation pair's
//! other half. It emits this node's attestation payload (the node id from
//! `CITADEL_NODE_ID`); the server plugin verifies it against mesh trust.

use citadel_spire_plugin::agent::proto::node_attestor_server::NodeAttestorServer;
use citadel_spire_plugin::agent::AgentAttestor;
use citadel_spire_plugin::config::config_server::ConfigServer;
use citadel_spire_plugin::{runtime, FILE_DESCRIPTOR_SET};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node_id = std::env::var("CITADEL_NODE_ID").unwrap_or_default();
    let attestor = AgentAttestor::new(node_id);
    let (mut health, health_service) = tonic_health::server::health_reporter();
    health
        .set_service_status("plugin", tonic_health::ServingStatus::Serving)
        .await;
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;
    let router = tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection)
        .add_service(NodeAttestorServer::new(attestor.clone()))
        .add_service(ConfigServer::new(attestor));
    runtime::run(router).await
}
