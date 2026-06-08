//! CP1 integration: a control plane observing a live (harness) mesh through an
//! observer node, and the read API serving the result.

use std::sync::{Arc, Mutex};

use citadel_control_plane::{api, ControlPlane, MemStore};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn observed_mesh() -> (ControlPlane<MemStore>, Vec<NodeId>, NodeId) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=5)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        6,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    mesh.run(24);

    let mut cp = ControlPlane::new(MemStore::new());
    cp.observe(mesh.node_mut(observer), 24);
    (cp, workers, observer)
}

#[test]
fn the_cp_reflects_the_mesh_through_an_observer() {
    let (cp, workers, _observer) = observed_mesh();

    let h = cp.fleet_health();
    assert_eq!(
        h.total,
        workers.len(),
        "5 workers (the observer is excluded)"
    );
    assert_eq!(h.trusted, workers.len(), "all workers healthy → trusted");
    assert!((h.mesh_health_pct - 100.0).abs() < 0.01);
    assert_eq!(cp.nodes().len(), workers.len());

    // Each worker's CP-derived trust matches the mesh's (and is backed by a
    // witness tally, not an assertion).
    for &w in &workers {
        let v = cp.node_view(&w).unwrap();
        assert_eq!(v.trust, "trusted");
        assert!(
            v.witnesses_total > 0,
            "trust is backed by verified verdicts"
        );
    }
}

#[test]
fn a_suspicious_node_surfaces_in_the_cp() {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=5)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        6,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    mesh.run(12);
    // Tamper a worker's measured state → its witnesses report mismatch.
    let bad = workers[4];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    assert_eq!(mesh.trust_of(workers[0], bad), Some(TrustState::Suspicious));

    let mut cp = ControlPlane::new(MemStore::new());
    cp.observe(mesh.node_mut(observer), 28);
    let v = cp.node_view(&bad).unwrap();
    assert_eq!(
        v.trust, "suspicious",
        "the CP derives the mismatch from verified verdicts"
    );
    assert!(cp.fleet_health().suspicious >= 1);
}

#[tokio::test]
async fn read_api_serves_health_and_nodes() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (cp, workers, _o) = observed_mesh();
    let shared = Arc::new(Mutex::new(cp));
    let app = api::router(shared);

    // GET /v1/mesh/health
    let resp = app
        .clone()
        .oneshot(Request::get("/v1/mesh/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let health: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(health["total"], workers.len());
    assert_eq!(health["trusted"], workers.len());

    // GET /v1/nodes
    let resp = app
        .clone()
        .oneshot(Request::get("/v1/nodes").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let nodes: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(nodes.as_array().unwrap().len(), workers.len());

    // GET /v1/nodes/{id}
    let resp = app
        .oneshot(
            Request::get(format!("/v1/nodes/{}", workers[0].to_hex()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[test]
fn agreement_recompute_matches_the_mesh_and_flags_dissent() {
    use std::collections::BTreeSet;

    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=5)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        6,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    mesh.run(12);
    let bad = workers[4];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);

    let mut cp = ControlPlane::new(MemStore::new());
    cp.observe(mesh.node_mut(observer), 28);

    // The CP recomputes the SAME assigned witness set the mesh uses.
    let bad_agreement = cp.agreement(&bad).unwrap();
    let cp_assigned: BTreeSet<String> = bad_agreement.assigned.iter().cloned().collect();
    let mesh_assigned: BTreeSet<String> = mesh
        .node(observer)
        .witness_ids_for(bad)
        .iter()
        .map(|w| w.to_hex())
        .collect();
    assert_eq!(
        cp_assigned, mesh_assigned,
        "CP recomputes the mesh's witness assignment"
    );

    // The tampered node has dissenters, with a reason (expected-vs-observed).
    assert!(
        !bad_agreement.dissenters.is_empty(),
        "tamper produces dissenting witnesses"
    );
    assert!(
        bad_agreement
            .dissenters
            .iter()
            .any(|d| !d.reasons.is_empty()),
        "dissent carries a reason code"
    );
    assert!(bad_agreement.agree < bad_agreement.assigned.len());

    // A healthy worker: its assigned witnesses agree, none dissent.
    let good = cp.agreement(&workers[0]).unwrap();
    assert!(good.dissenters.is_empty(), "healthy node has no dissent");
    assert!(
        good.agree >= good.quorum_threshold,
        "quorum of assigned witnesses agree"
    );
}

#[tokio::test]
async fn read_api_serves_agreement() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (cp, workers, _o) = observed_mesh();
    let app = api::router(Arc::new(Mutex::new(cp)));
    let resp = app
        .oneshot(
            Request::get(format!("/v1/nodes/{}/agreement", workers[0].to_hex()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let a: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(a["assigned"].is_array());
    assert!(a["quorum_threshold"].is_number());
}
