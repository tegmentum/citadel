//! Citadel SPIRE NodeAttestor as a **go-plugin external plugin** — the binary a
//! live SPIRE server launches. It speaks HashiCorp go-plugin's handshake (the
//! protocol SPIRE's plugin SDK uses): verify the magic cookie, serve gRPC on a
//! unix socket (health + reflection + the NodeAttestor/Config services), and
//! print the handshake line to stdout so SPIRE can connect.
//!
//! Trust source: a JSON file (`CITADEL_TRUST_FILE`) of `{node-hex: level}` for
//! standalone/demo runs; production points this at the control plane
//! (`TrustProvider`). See README.md for the Docker harness.
//!
//! Note: SPIRE enables go-plugin AutoMTLS (`PLUGIN_CLIENT_CERT`). This scaffold
//! serves plaintext over the unix socket and logs if AutoMTLS is requested; the
//! mTLS cert exchange is the documented remaining deployment step.

use std::collections::HashMap;
use std::env;

use citadel_mesh::NodeId;
use citadel_spiffe::{NodeTrustView, TrustLevel};
use citadel_spire_plugin::config::config_server::ConfigServer;
use citadel_spire_plugin::nodeattestor::node_attestor_server::NodeAttestorServer;
use citadel_spire_plugin::{
    CitadelPlugin, TrustView, FILE_DESCRIPTOR_SET, MAGIC_COOKIE_KEY, MAGIC_COOKIE_VALUE,
};
use tokio_stream::wrappers::UnixListenerStream;

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

/// Pick the protocol version from the host's `PLUGIN_PROTOCOL_VERSIONS` list; the
/// SPIRE plugin SDK uses version 1.
fn negotiate_version() -> u32 {
    env::var("PLUGIN_PROTOCOL_VERSIONS")
        .ok()
        .and_then(|vs| {
            vs.split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .max()
        })
        .unwrap_or(1)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // go-plugin magic-cookie handshake: refuse to run outside SPIRE.
    if env::var(MAGIC_COOKIE_KEY).ok().as_deref() != Some(MAGIC_COOKIE_VALUE) {
        eprintln!(
            "This binary is a SPIRE NodeAttestor plugin (go-plugin) and is not meant to be \
             executed directly. SPIRE launches it. See README.md."
        );
        std::process::exit(1);
    }
    if env::var("PLUGIN_CLIENT_CERT").is_ok() {
        eprintln!(
            "citadel-spire-plugin: AutoMTLS requested by host (PLUGIN_CLIENT_CERT set) but this \
             scaffold serves plaintext; configure SPIRE without AutoMTLS, or see README for the \
             mTLS step."
        );
    }

    let version = negotiate_version();
    let socket = env::temp_dir().join(format!("citadel-spire-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;

    let plugin = CitadelPlugin::new(FileTrust::from_env());

    // go-plugin health: the client waits for service "plugin" to be SERVING.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_service_status("plugin", tonic_health::ServingStatus::Serving)
        .await;

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    // Emit the go-plugin handshake line to stdout (nothing else may touch stdout):
    //   CoreProtocolVersion|AppProtocolVersion|network|address|protocol|serverCert
    println!("1|{version}|unix|{}|grpc|", socket.display());
    use std::io::Write;
    std::io::stdout().flush()?;

    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection)
        .add_service(NodeAttestorServer::new(plugin.clone()))
        .add_service(ConfigServer::new(plugin))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;

    let _ = std::fs::remove_file(&socket);
    Ok(())
}
