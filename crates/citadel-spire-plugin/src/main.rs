//! Citadel **server-side** SPIRE NodeAttestor as a go-plugin external plugin —
//! the binary a live SPIRE server launches. It returns an agent identity +
//! citadel: selectors only for nodes the mesh currently Verifies. The go-plugin
//! handshake + AutoMTLS + serving live in [`citadel_spire_plugin::runtime`];
//! trust source is a JSON file (`CITADEL_TRUST_FILE`) for demo runs.

use std::collections::HashMap;
use std::env;

use citadel_mesh::NodeId;
use citadel_spiffe::{NodeTrustView, TrustLevel};
use citadel_spire_plugin::config::config_server::ConfigServer;
use citadel_spire_plugin::nodeattestor::node_attestor_server::NodeAttestorServer;
use citadel_spire_plugin::{runtime, CitadelPlugin, TrustView, FILE_DESCRIPTOR_SET};

/// A file-backed trust source for standalone/demo runs.
struct FileTrust {
    levels: HashMap<String, TrustLevel>,
}

impl FileTrust {
    fn from_env() -> Self {
        let mut levels = HashMap::new();
        if let Ok(path) = env::var("CITADEL_TRUST_FILE") {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&data) {
                    for (k, v) in map {
                        levels.insert(k.to_lowercase(), parse_level(&v));
                    }
                }
            }
        }
        FileTrust { levels }
    }
}

fn parse_level(s: &str) -> TrustLevel {
    match s.to_lowercase().as_str() {
        "verified" => TrustLevel::Verified,
        "quarantined" => TrustLevel::Quarantined,
        "revoked" => TrustLevel::Revoked,
        _ => TrustLevel::Suspect,
    }
}

impl TrustView for FileTrust {
    fn node_trust_view(&self, node: &NodeId) -> NodeTrustView {
        let key = node
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let known = self.levels.get(&key).copied();
        let trust_level = known.unwrap_or(TrustLevel::Suspect);
        let (agree, total) = match (known, trust_level) {
            (None, _) => (0, 0),
            (Some(_), TrustLevel::Verified) => (3, 3),
            (Some(_), _) => (2, 3),
        };
        NodeTrustView {
            trust_level,
            quorum_agree: agree,
            quorum_total: total,
            ima_policy: None,
            tpm_ak: None,
            mma_profile: None,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let plugin = CitadelPlugin::new(FileTrust::from_env());
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
        .add_service(NodeAttestorServer::new(plugin.clone()))
        .add_service(ConfigServer::new(plugin));
    runtime::run(router).await
}
