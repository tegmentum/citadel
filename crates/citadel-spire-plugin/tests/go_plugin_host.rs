//! Emulates SPIRE's go-plugin *host*: launch the plugin binary with the magic
//! cookie + protocol-version env, parse its stdout handshake line, dial the unix
//! socket, confirm health is SERVING, Configure, then Attest — proving the
//! external-plugin protocol end to end without a live SPIRE.

use std::process::Stdio;

use citadel_spire_plugin::config::config_client::ConfigClient;
use citadel_spire_plugin::config::{ConfigureRequest, CoreConfiguration};
use citadel_spire_plugin::nodeattestor::attest_response::Response as AttestResp;
use citadel_spire_plugin::nodeattestor::node_attestor_client::NodeAttestorClient;
use citadel_spire_plugin::nodeattestor::{attest_request, AttestRequest};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tonic::transport::{Endpoint, Uri};

#[tokio::test]
async fn behaves_as_a_go_plugin_external_plugin() {
    // A trust file: one Verified node, one Quarantined node.
    let verified = "01".repeat(32);
    let quarantined = "02".repeat(32);
    let trust_json = format!("{{\"{verified}\":\"verified\",\"{quarantined}\":\"quarantined\"}}");
    let trust_file = std::env::temp_dir().join("citadel-spire-trust-test.json");
    std::fs::write(&trust_file, trust_json).unwrap();

    // Launch the plugin as go-plugin would.
    let mut child = Command::new(env!("CARGO_BIN_EXE_citadel-spire-plugin"))
        .env("NodeAttestor", "NodeAttestor") // magic cookie
        .env("PLUGIN_PROTOCOL_VERSIONS", "1")
        .env("CITADEL_TRUST_FILE", &trust_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("launch plugin");

    // Parse the handshake line: CoreProto|AppProto|network|addr|protocol|cert
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
        .await
        .expect("handshake timed out")
        .unwrap()
        .expect("handshake line");
    let parts: Vec<&str> = line.split('|').collect();
    assert_eq!(parts[0], "1", "core protocol version");
    assert_eq!(parts[1], "1", "app protocol version");
    assert_eq!(parts[2], "unix");
    assert_eq!(parts[4], "grpc");
    let socket = parts[3].to_string();

    // Dial the unix socket exactly as the go-plugin client does.
    let connect = move |_: Uri| {
        let socket = socket.clone();
        async move {
            Ok::<_, std::io::Error>(TokioIo::new(tokio::net::UnixStream::connect(socket).await?))
        }
    };
    let channel = Endpoint::try_from("http://[::1]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(connect))
        .await
        .expect("dial plugin socket");

    // go-plugin waits for the health service "plugin" to be SERVING.
    let mut health = tonic_health::pb::health_client::HealthClient::new(channel.clone());
    let status = health
        .check(tonic_health::pb::HealthCheckRequest {
            service: "plugin".to_string(),
        })
        .await
        .expect("health check")
        .into_inner()
        .status;
    assert_eq!(
        status,
        tonic_health::pb::health_check_response::ServingStatus::Serving as i32
    );

    // Configure with the trust domain (SPIRE core config).
    ConfigClient::new(channel.clone())
        .configure(ConfigureRequest {
            core_configuration: Some(CoreConfiguration {
                trust_domain: "citadel.local".to_string(),
            }),
            hcl_configuration: String::new(),
        })
        .await
        .expect("configure");

    // Attest the Verified node → identity + selectors.
    let mut attestor = NodeAttestorClient::new(channel);
    let payload = serde_json::json!({ "node_id": verified })
        .to_string()
        .into_bytes();
    let req = AttestRequest {
        request: Some(attest_request::Request::Payload(payload)),
    };
    let mut stream = attestor
        .attest(tokio_stream::once(req))
        .await
        .unwrap()
        .into_inner();
    match stream.message().await.unwrap().unwrap().response.unwrap() {
        AttestResp::AgentAttributes(a) => {
            assert!(a.spiffe_id.starts_with("spiffe://citadel.local/node/"));
            assert!(a
                .selector_values
                .contains(&"citadel:trust-level=verified".to_string()));
        }
        AttestResp::Challenge(_) => panic!("unexpected challenge"),
    }

    let _ = child.kill().await;
    let _ = std::fs::remove_file(&trust_file);
}
