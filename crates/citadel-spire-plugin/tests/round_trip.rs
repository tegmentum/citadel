//! Self-contained gRPC round-trip (no SPIRE): a SPIRE server would Attest via
//! this; a Verified node gets an identity + selectors, a Quarantined one is
//! denied — so SPIRE won't issue/renew its SVID.

use citadel_mesh::NodeId;
use citadel_spiffe::{NodeTrustView, TrustLevel};
use citadel_spire_plugin::config::config_client::ConfigClient;
use citadel_spire_plugin::config::{ConfigureRequest, CoreConfiguration};
use citadel_spire_plugin::nodeattestor::attest_response::Response as AttestResp;
use citadel_spire_plugin::nodeattestor::node_attestor_client::NodeAttestorClient;
use citadel_spire_plugin::nodeattestor::{attest_request, AttestRequest};
use citadel_spire_plugin::{router, AttestationPayload, CitadelPlugin, TrustView};
use tokio_stream::wrappers::TcpListenerStream;

struct Mock;
impl TrustView for Mock {
    fn node_trust_view(&self, node: &NodeId) -> NodeTrustView {
        let trust_level = match node.0[0] {
            1 => TrustLevel::Verified,
            2 => TrustLevel::Quarantined,
            _ => TrustLevel::Suspect,
        };
        NodeTrustView {
            trust_level,
            quorum_agree: 3,
            quorum_total: 3,
            ima_policy: Some("baseline-v3".to_string()),
            tpm_ak: None,
            mma_profile: None,
            tpm_spec: None,
        }
    }
}

fn payload(seed: &str) -> AttestRequest {
    let p = serde_json::to_vec(&AttestationPayload {
        node_id: seed.repeat(32),
    })
    .unwrap();
    AttestRequest {
        request: Some(attest_request::Request::Payload(p)),
    }
}

#[tokio::test]
async fn attest_gates_identity_on_mesh_trust() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        router(CitadelPlugin::new(Mock))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let endpoint = format!("http://{addr}");

    // Configure sets the trust domain (the SPIRE core config path).
    let mut cfg = ConfigClient::connect(endpoint.clone()).await.unwrap();
    cfg.configure(ConfigureRequest {
        core_configuration: Some(CoreConfiguration {
            trust_domain: "citadel.local".to_string(),
        }),
        hcl_configuration: String::new(),
    })
    .await
    .unwrap();

    let mut client = NodeAttestorClient::connect(endpoint).await.unwrap();

    // A Verified node attests: gets its SPIFFE id + derived citadel: selectors.
    let mut resp = client
        .attest(tokio_stream::once(payload("01")))
        .await
        .unwrap()
        .into_inner();
    let msg = resp.message().await.unwrap().unwrap();
    match msg.response.unwrap() {
        AttestResp::AgentAttributes(a) => {
            assert!(a.spiffe_id.starts_with("spiffe://citadel.local/node/"));
            assert!(a
                .selector_values
                .contains(&"citadel:trust-level=verified".to_string()));
            assert!(a
                .selector_values
                .contains(&"citadel:ima-policy=baseline-v3".to_string()));
            assert!(
                a.can_reattest,
                "re-attestation re-checks trust (continuity)"
            );
        }
        AttestResp::Challenge(_) => panic!("unexpected challenge"),
    }

    // A Quarantined node is denied — SPIRE will not issue/renew its SVID.
    let denied = client.attest(tokio_stream::once(payload("02"))).await;
    let status = match denied {
        Err(s) => s,
        Ok(r) => {
            let mut s = r.into_inner();
            s.message().await.unwrap_err()
        }
    };
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(status.message().contains("quarantined"));
}
