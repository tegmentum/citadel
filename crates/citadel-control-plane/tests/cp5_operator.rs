//! CP5 — the operator write path: an authorized, operator-signed action relays
//! an authority-signed manifest into the mesh, which adopts it; unauthorized or
//! forged writes are refused; everything relayed is audited (tamper-evident).

use citadel_control_plane::{ControlPlane, MemStore, OperatorAction, WriteError};
use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::crypto::{MeshKeypair, Signature};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{ReferenceEntry, ReferenceManifest, Validity};
use citadel_mesh::NodeId;

fn a_manifest(authority: &MeshKeypair) -> ReferenceManifest {
    ReferenceManifest::issue(
        authority,
        "",
        vec![ReferenceEntry::new(0, vec![7u8; 32], Validity::always())],
        vec![],
    )
}

fn mesh_with_observer() -> (Mesh, Vec<NodeId>, NodeId) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 0,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=4)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        5,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    (mesh, workers, observer)
}

#[test]
fn an_authorized_policy_publish_is_adopted_by_the_mesh_and_audited() {
    let (mut mesh, workers, observer) = mesh_with_observer();
    let authority = MeshKeypair::from_seed([200; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));

    let operator = MeshKeypair::from_seed([50; 32]);
    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());

    let manifest = a_manifest(&authority);
    let cid = manifest.content_id();
    let action = OperatorAction::sign(&operator, "publish-policy", cid);

    let res = cp.publish_policy(&action, &manifest, mesh.node_mut(observer), 5);
    assert_eq!(res, Ok(cid));
    mesh.run(10);

    for &w in &workers {
        assert!(
            mesh.node(w).has_reference_manifest(cid),
            "worker adopted the published policy"
        );
    }
    // Recorded in the tamper-evident operator audit.
    let audit = cp.operator_audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].kind, "publish-policy");
    assert!(cp.operator_audit_ok());
}

#[test]
fn unauthorized_target_mismatch_and_forged_writes_are_refused() {
    let (mut mesh, _w, observer) = mesh_with_observer();
    let authority = MeshKeypair::from_seed([200; 32]);
    let operator = MeshKeypair::from_seed([50; 32]);
    let stranger = MeshKeypair::from_seed([99; 32]);
    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());

    let manifest = a_manifest(&authority);
    let cid = manifest.content_id();

    // An unregistered operator.
    let unauth = OperatorAction::sign(&stranger, "publish-policy", cid);
    assert_eq!(
        cp.publish_policy(&unauth, &manifest, mesh.node_mut(observer), 1),
        Err(WriteError::Unauthorized)
    );

    // Authorizes a different target than the supplied manifest.
    let mismatch = OperatorAction::sign(&operator, "publish-policy", [0xAB; 32]);
    assert_eq!(
        cp.publish_policy(&mismatch, &manifest, mesh.node_mut(observer), 1),
        Err(WriteError::TargetMismatch)
    );

    // A manifest whose authority signature doesn't verify.
    let mut forged = a_manifest(&authority);
    forged.signature = Signature::zero();
    let fcid = forged.content_id();
    let action = OperatorAction::sign(&operator, "publish-policy", fcid);
    assert_eq!(
        cp.publish_policy(&action, &forged, mesh.node_mut(observer), 1),
        Err(WriteError::BadArtifact)
    );

    // Nothing refused was relayed or audited.
    assert!(cp.operator_audit().is_empty());
}

#[test]
fn the_operator_audit_chain_links_and_verifies() {
    let (mut mesh, _w, observer) = mesh_with_observer();
    let authority = MeshKeypair::from_seed([200; 32]);
    let operator = MeshKeypair::from_seed([50; 32]);
    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());

    for i in 0..3u64 {
        // Distinct manifests (vary the entry digest) → distinct content ids.
        let m = ReferenceManifest::issue(
            &authority,
            "",
            vec![ReferenceEntry::new(
                0,
                vec![i as u8; 32],
                Validity::always(),
            )],
            vec![],
        );
        let cid = m.content_id();
        let action = OperatorAction::sign(&operator, "publish-policy", cid);
        cp.publish_policy(&action, &m, mesh.node_mut(observer), i + 1)
            .unwrap();
    }
    let audit = cp.operator_audit();
    assert_eq!(audit.len(), 3);
    // Each link commits to the previous.
    assert_eq!(audit[1].prev_hash, audit[0].hash);
    assert_eq!(audit[2].prev_hash, audit[1].hash);
    assert!(cp.operator_audit_ok());
}

#[tokio::test]
async fn read_api_serves_the_operator_audit() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    let (mut mesh, _w, observer) = mesh_with_observer();
    let authority = MeshKeypair::from_seed([200; 32]);
    let operator = MeshKeypair::from_seed([50; 32]);
    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());
    let m = a_manifest(&authority);
    let action = OperatorAction::sign(&operator, "publish-policy", m.content_id());
    cp.publish_policy(&action, &m, mesh.node_mut(observer), 1)
        .unwrap();

    let app = citadel_control_plane::api::router(Arc::new(Mutex::new(cp)));
    let resp = app
        .oneshot(Request::get("/v1/audit").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let audit: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(audit.as_array().unwrap().len(), 1);
    assert_eq!(audit[0]["kind"], "publish-policy");
}
