//! Emulates SPIRE's go-plugin host *with AutoMTLS*: generate a client cert, pass
//! it as PLUGIN_CLIENT_CERT, launch the plugin, read the advertised server cert
//! from the handshake's 6th field, connect over mutual TLS, and Attest — proving
//! the AutoMTLS handshake end to end without a live SPIRE.

use std::process::Stdio;
use std::sync::Arc;

use base64::Engine;
use citadel_spire_plugin::nodeattestor::attest_response::Response as AttestResp;
use citadel_spire_plugin::nodeattestor::node_attestor_client::NodeAttestorClient;
use citadel_spire_plugin::nodeattestor::{attest_request, AttestRequest};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tonic::transport::{Endpoint, Uri};

#[tokio::test]
async fn loads_and_attests_over_automtls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // The host's AutoMTLS client identity.
    let key = rcgen::KeyPair::generate().unwrap();
    let client = rcgen::CertificateParams::new(vec!["citadel-host".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let client_pem = client.pem();
    let client_der = client.der().to_vec();
    let client_key_der = key.serialize_der();

    let verified = "01".repeat(32);
    let trust_file = std::env::temp_dir().join("citadel-spire-automtls-trust.json");
    std::fs::write(&trust_file, format!("{{\"{verified}\":\"verified\"}}")).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_citadel-spire-plugin"))
        .env("NodeAttestor", "NodeAttestor")
        .env("PLUGIN_PROTOCOL_VERSIONS", "1")
        .env("PLUGIN_CLIENT_CERT", &client_pem) // triggers AutoMTLS
        .env("CITADEL_TRUST_FILE", &trust_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("launch plugin");

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
        .await
        .expect("handshake timeout")
        .unwrap()
        .expect("handshake line");
    let parts: Vec<&str> = line.split('|').collect();
    let socket = parts[3].to_string();
    let server_cert_b64 = parts[5];
    assert!(
        !server_cert_b64.is_empty(),
        "AutoMTLS advertises a server cert in field 6"
    );
    let server_der = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(server_cert_b64)
        .expect("decode server cert");

    // Client mTLS config: present our client cert, trust the advertised server cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(server_der)).unwrap();
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from(client_der)],
            PrivateKeyDer::try_from(client_key_der).unwrap(),
        )
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));

    let connect = move |_: Uri| {
        let socket = socket.clone();
        let connector = connector.clone();
        async move {
            let sock = tokio::net::UnixStream::connect(socket).await?;
            let name = ServerName::try_from("localhost").unwrap();
            let stream = connector.connect(name, sock).await?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }
    };
    let channel = Endpoint::try_from("https://localhost")
        .unwrap()
        .connect_with_connector(tower::service_fn(connect))
        .await
        .expect("mTLS dial");

    // Attest a Verified node over the mTLS channel.
    let mut client = NodeAttestorClient::new(channel);
    let payload = serde_json::json!({ "node_id": verified })
        .to_string()
        .into_bytes();
    let req = AttestRequest {
        request: Some(attest_request::Request::Payload(payload)),
    };
    let mut stream = client
        .attest(tokio_stream::once(req))
        .await
        .unwrap()
        .into_inner();
    match stream.message().await.unwrap().unwrap().response.unwrap() {
        AttestResp::AgentAttributes(a) => {
            assert!(a.spiffe_id.starts_with("spiffe://citadel.local/node/"));
        }
        AttestResp::Challenge(_) => panic!("unexpected challenge"),
    }

    let _ = child.kill().await;
    let _ = std::fs::remove_file(&trust_file);
}
