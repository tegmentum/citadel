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
//! AutoMTLS: when SPIRE passes `PLUGIN_CLIENT_CERT` (its default), the plugin
//! serves mutual TLS and advertises its server cert in the handshake (see
//! [`citadel_spire_plugin::mtls`]); otherwise it serves plaintext.

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
    // AutoMTLS: if the host passed its client cert, serve mTLS and advertise our
    // server cert in the handshake; otherwise plaintext.
    let auto_mtls = env::var("PLUGIN_CLIENT_CERT").ok();

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

    let router = tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection)
        .add_service(NodeAttestorServer::new(plugin.clone()))
        .add_service(ConfigServer::new(plugin));

    let server_cert = match &auto_mtls {
        Some(ca) => Some(citadel_spire_plugin::mtls::build(ca)?),
        None => None,
    };

    // Emit the go-plugin handshake line to stdout (nothing else may touch stdout):
    //   CoreProtocolVersion|AppProtocolVersion|network|address|protocol|serverCert
    let cert_field = server_cert
        .as_ref()
        .map(|s| citadel_spire_plugin::mtls::handshake_cert_field(&s.cert_der))
        .unwrap_or_default();
    println!("1|{version}|unix|{}|grpc|{cert_field}", socket.display());
    use std::io::Write;
    std::io::stdout().flush()?;

    match server_cert {
        Some(tls) => {
            // mTLS: terminate TLS per connection, serve plaintext gRPC over it.
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.config);
            let incoming = async_stream::stream! {
                loop {
                    match listener.accept().await {
                        Ok((sock, _)) => match acceptor.accept(sock).await {
                            Ok(s) => yield Ok::<_, std::io::Error>(TlsConn(s)),
                            Err(e) => eprintln!("citadel-spire-plugin: tls accept: {e}"),
                        },
                        Err(e) => yield Err(e),
                    }
                }
            };
            router.serve_with_incoming(incoming).await?;
        }
        None => {
            router
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await?;
        }
    }

    let _ = std::fs::remove_file(&socket);
    Ok(())
}

/// A TLS-terminated unix connection presented to tonic (AutoMTLS path).
struct TlsConn(tokio_rustls::server::TlsStream<tokio::net::UnixStream>);

impl tonic::transport::server::Connected for TlsConn {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl tokio::io::AsyncRead for TlsConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TlsConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
