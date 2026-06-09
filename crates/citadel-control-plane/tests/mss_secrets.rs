//! MSS4: secret-release decisions surface in the control plane + API. The
//! observer sees the signed release gossip and tallies it; the CP ingests the
//! decisions (a granted one and a denied one) and serves them.

use std::sync::{Arc, Mutex};

use citadel_control_plane::{api, ControlPlane, MemStore};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

const SECRET_OK: [u8; 32] = [0xA1; 32];
const SECRET_BAD: [u8; 32] = [0xB2; 32];

fn observed_release_mesh() -> (ControlPlane<MemStore>, usize, usize) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        20,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    mesh.run(16);

    // A trusted node is granted release.
    mesh.node_mut(workers[0])
        .request_release(SECRET_OK, [1u8; 32], 3, 5, 100, 20);
    mesh.run(10);

    // A compromised node requests a different secret and is denied.
    let bad = workers[5];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(mesh.trust_of(workers[1], bad), Some(TrustState::Suspicious));
    mesh.node_mut(bad)
        .request_release(SECRET_BAD, [2u8; 32], 3, 5, 100, 40);
    mesh.run(12);

    // The control plane ingests members + the observer's release decisions.
    let mut cp = ControlPlane::new(MemStore::new());
    cp.observe(mesh.node_mut(observer), 52);
    cp.poll_releases(mesh.node(observer));

    let releases = cp.releases();
    let granted = releases.iter().filter(|r| r.authorized).count();
    let denied = releases.iter().filter(|r| !r.authorized).count();
    (cp, granted, denied)
}

#[test]
fn the_cp_surfaces_granted_and_denied_releases() {
    let (cp, granted, denied) = observed_release_mesh();
    let releases = cp.releases();
    assert_eq!(releases.len(), 2, "both release requests are tracked");
    assert_eq!(granted, 1, "the trusted node's release is authorized");
    assert_eq!(denied, 1, "the compromised node's release is denied");

    // The granted decision carries a real quorum tally.
    let ok = releases.iter().find(|r| r.authorized).unwrap();
    assert!(
        ok.approvals >= ok.quorum,
        "granted = approvals met the quorum"
    );
    let bad = releases.iter().find(|r| !r.authorized).unwrap();
    assert!(bad.approvals < bad.quorum, "denied = quorum not reached");
}

#[tokio::test]
async fn read_api_serves_secrets() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (cp, _, _) = observed_release_mesh();
    let app = api::router(Arc::new(Mutex::new(cp)));
    let resp = app
        .oneshot(Request::get("/v1/secrets").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let secrets: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(secrets.as_array().unwrap().len(), 2);
    assert!(secrets
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["authorized"] == true));
    assert!(secrets
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["authorized"] == false));
}
