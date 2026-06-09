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

#[tokio::test]
async fn live_post_policies_validates_then_host_relays_to_the_mesh() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    let (mut mesh, workers, observer) = mesh_with_observer();
    let authority = MeshKeypair::from_seed([200; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));
    let operator = MeshKeypair::from_seed([50; 32]);
    let stranger = MeshKeypair::from_seed([99; 32]);

    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());
    cp.observe(mesh.node_mut(observer), 7); // establish the current tick
    let shared = Arc::new(Mutex::new(cp));
    let app = citadel_control_plane::api::router(shared.clone());

    let manifest = a_manifest(&authority);
    let cid = manifest.content_id();

    // An unregistered operator over HTTP → 403, nothing enqueued.
    let unauth = OperatorAction::sign(&stranger, "publish-policy", cid);
    let body =
        serde_json::to_vec(&serde_json::json!({ "action": unauth, "manifest": manifest })).unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::post("/v1/policies")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(shared.lock().unwrap().drain_pending_manifests().is_empty());

    // An authorized publish over HTTP → 200 + content id; it is enqueued.
    let action = OperatorAction::sign(&operator, "publish-policy", cid);
    let body =
        serde_json::to_vec(&serde_json::json!({ "action": action, "manifest": manifest })).unwrap();
    let resp = app
        .oneshot(
            Request::post("/v1/policies")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["content_id"], citadel_mesh::NodeId(cid).to_hex());

    // The host loop drains the queue and relays through the observer node.
    let pending = shared.lock().unwrap().drain_pending_manifests();
    assert_eq!(pending.len(), 1);
    for m in pending {
        mesh.node_mut(observer).broadcast_reference_manifest(m);
    }
    mesh.run(10);
    for &w in &workers {
        assert!(
            mesh.node(w).has_reference_manifest(cid),
            "mesh adopted the HTTP-published policy"
        );
    }
    // The accepted write was audited.
    assert_eq!(shared.lock().unwrap().operator_audit().len(), 1);
}

#[test]
fn cp_relays_an_operator_quarantine_approval_and_the_mesh_enacts() {
    use citadel_mesh::quarantine::{OperatorQuarantineApproval, QuarantineScope};
    use citadel_mesh::state::TrustState;

    // A mesh with a tampered (suspicious) subject + a control-plane observer.
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 4,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        7,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    mesh.run(12);
    let subject = workers[5];
    mesh.measured_state_change(subject, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(
        mesh.trust_of(workers[0], subject),
        Some(TrustState::Suspicious)
    );

    // The operator the CP trusts; authorize it on every node so approvals count.
    let operator = MeshKeypair::from_seed([222; 32]);
    mesh.authorize_operator_key_all(operator.public());
    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());

    // A witness proposes full isolation; witnesses approve but it is gated on
    // the operator, so it does not enact.
    let pid = mesh.node_mut(workers[0]).propose_and_broadcast_quarantine(
        subject,
        QuarantineScope::FullIsolation,
        30,
    );
    mesh.run(10);
    assert_eq!(mesh.node(workers[1]).quarantine_of(subject), None);

    // The operator signs the approval; the CP validates + audits + relays it
    // through its observer node — and the mesh enacts.
    let approval = OperatorQuarantineApproval::sign(&operator, pid, 41);
    let res = cp.relay_quarantine_approval(approval, mesh.node_mut(observer), 41);
    assert_eq!(res, Ok(pid));
    mesh.run(10);

    for &w in &workers {
        if w == subject {
            continue;
        }
        assert_eq!(
            mesh.node(w).quarantine_of(subject),
            Some(QuarantineScope::FullIsolation),
            "the CP-relayed operator approval enacted full isolation at {w}"
        );
    }
    // The CP audited the relayed approval.
    let audit = cp.operator_audit();
    assert!(audit.iter().any(|e| e.kind == "quarantine-approval"));
    assert!(cp.operator_audit_ok());
}

#[test]
fn an_unregistered_operator_quarantine_approval_is_refused() {
    use citadel_mesh::quarantine::OperatorQuarantineApproval;
    let stranger = MeshKeypair::from_seed([7; 32]);
    let mut cp = ControlPlane::new(MemStore::new());
    // stranger is not registered.
    let approval = OperatorQuarantineApproval::sign(&stranger, [9u8; 32], 1);
    assert_eq!(
        cp.submit_quarantine_approval(approval, 1),
        Err(WriteError::Unauthorized)
    );
    assert!(cp.operator_audit().is_empty());
}
