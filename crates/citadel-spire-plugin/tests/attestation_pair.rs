//! The full SPIRE NodeAttestor pair, Citadel-gated: launch the agent plugin (it
//! emits the node's payload), feed that payload to the server plugin's Attest,
//! and confirm it issues an identity for a mesh-Verified node — no live SPIRE.

use std::process::Stdio;

use citadel_spire_plugin::agent::proto::node_attestor_client::NodeAttestorClient as AgentClient;
use citadel_spire_plugin::agent::proto::{payload_or_challenge_response, Challenge};
use citadel_spire_plugin::nodeattestor::attest_response::Response as AttestResp;
use citadel_spire_plugin::nodeattestor::node_attestor_client::NodeAttestorClient as ServerClient;
use citadel_spire_plugin::nodeattestor::{attest_request, AttestRequest};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tonic::transport::{Channel, Endpoint, Uri};

/// Launch a plugin binary (plaintext, no AutoMTLS), return (child, socket path).
async fn launch(bin: &str, envs: &[(&str, &str)]) -> (Child, String) {
    let mut cmd = Command::new(bin);
    cmd.env("NodeAttestor", "NodeAttestor")
        .env("PLUGIN_PROTOCOL_VERSIONS", "1");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
        .await
        .expect("handshake timeout")
        .unwrap()
        .expect("handshake line");
    let socket = line.split('|').nth(3).unwrap().to_string();
    (child, socket)
}

async fn dial(socket: String) -> Channel {
    let connect = move |_: Uri| {
        let socket = socket.clone();
        async move {
            Ok::<_, std::io::Error>(TokioIo::new(tokio::net::UnixStream::connect(socket).await?))
        }
    };
    Endpoint::try_from("http://localhost")
        .unwrap()
        .connect_with_connector(tower::service_fn(connect))
        .await
        .unwrap()
}

#[tokio::test]
async fn agent_payload_attests_against_the_server() {
    let node_id = "07".repeat(32);
    let trust_file = std::env::temp_dir().join("citadel-spire-pair-trust.json");
    std::fs::write(&trust_file, format!("{{\"{node_id}\":\"verified\"}}")).unwrap();
    let bin = env!("CARGO_BIN_EXE_citadel-spire-plugin");
    let agent_bin = env!("CARGO_BIN_EXE_citadel-spire-agent-plugin");

    // Agent plugin emits this node's payload.
    let (mut agent, agent_sock) = launch(agent_bin, &[("CITADEL_NODE_ID", &node_id)]).await;
    let mut agent_client = AgentClient::new(dial(agent_sock).await);
    let mut stream = agent_client
        .aid_attestation(tokio_stream::empty::<Challenge>())
        .await
        .unwrap()
        .into_inner();
    let payload = match stream.message().await.unwrap().unwrap().data.unwrap() {
        payload_or_challenge_response::Data::Payload(p) => p,
        _ => panic!("expected payload first"),
    };
    // The agent's payload names this node.
    assert!(String::from_utf8_lossy(&payload).contains(&node_id));

    // Server plugin verifies that payload against mesh trust → issues identity.
    let (mut server, server_sock) =
        launch(bin, &[("CITADEL_TRUST_FILE", trust_file.to_str().unwrap())]).await;
    let mut server_client = ServerClient::new(dial(server_sock).await);
    let req = AttestRequest {
        request: Some(attest_request::Request::Payload(payload)),
    };
    let mut resp = server_client
        .attest(tokio_stream::once(req))
        .await
        .unwrap()
        .into_inner();
    match resp.message().await.unwrap().unwrap().response.unwrap() {
        AttestResp::AgentAttributes(a) => {
            assert_eq!(
                a.spiffe_id,
                format!("spiffe://citadel.local/node/{node_id}")
            );
        }
        AttestResp::Challenge(_) => panic!("unexpected challenge"),
    }

    let _ = agent.kill().await;
    let _ = server.kill().await;
    let _ = std::fs::remove_file(&trust_file);
}
