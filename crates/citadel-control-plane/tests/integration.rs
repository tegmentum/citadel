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

#[test]
fn evidence_durability_is_proven_from_holder_receipts() {
    use citadel_mesh::evidence::payload_hash;

    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        log_window_size: 8,
        evidence_replication: true,
        evidence_data_shards: 3,
        evidence_parity_shards: 2,
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

    // Seal + ship a window on one worker; holders return signed receipts.
    let origin = workers[0];
    for i in 0..12u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("event-{i}").as_bytes()));
    }
    mesh.run(20);

    let mut cp = ControlPlane::new(MemStore::new());
    cp.observe(mesh.node_mut(observer), 20);
    cp.poll_durability(mesh.node(origin));

    let v = cp.evidence_view(&origin).unwrap();
    assert!(v.records_total >= 1, "the sealed window is tracked");
    let r = &v.records[0];
    assert_eq!(r.threshold, 3, "3 data shards");
    assert_eq!(r.total, 5, "3+2 = 5 fragments");
    assert!(r.holders_acked >= 3, "≥ threshold holders acknowledged");
    assert!(r.reconstructable, "≥ threshold acks → reconstructable");
    assert!((v.durability_pct - 100.0).abs() < 0.01);
    assert!((cp.fleet_health().evidence_durability_pct - 100.0).abs() < 0.01);
}

#[tokio::test]
async fn read_api_serves_evidence() {
    use axum::body::Body;
    use axum::http::Request;
    use citadel_mesh::evidence::payload_hash;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        log_window_size: 8,
        evidence_replication: true,
        evidence_data_shards: 3,
        evidence_parity_shards: 2,
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
    let origin = workers[0];
    for i in 0..12u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("e-{i}").as_bytes()));
    }
    mesh.run(20);
    let mut cp = ControlPlane::new(MemStore::new());
    cp.observe(mesh.node_mut(observer), 20);
    cp.poll_durability(mesh.node(origin));

    let app = api::router(Arc::new(Mutex::new(cp)));
    let resp = app
        .oneshot(
            Request::get(format!("/v1/nodes/{}/evidence", origin.to_hex()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let e: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(e["records"].is_array());
    assert!(e["records_total"].as_u64().unwrap() >= 1);
}

#[test]
fn the_forensic_timeline_records_what_changed() {
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

    let mut cp = ControlPlane::new(MemStore::new());
    mesh.run(12);
    cp.observe(mesh.node_mut(observer), 12); // healthy → enrolled + trusted

    let bad = workers[4];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(16);
    cp.observe(mesh.node_mut(observer), 28); // tamper → trusted → suspicious

    let tl = cp.timeline(&bad);
    assert!(
        tl.iter().any(|e| e.kind == "enrolled"),
        "enrolment is on the timeline"
    );
    let transition = tl
        .iter()
        .find(|e| e.kind == "trust-transition" && e.detail.contains("suspicious"));
    assert!(
        transition.is_some(),
        "the trust drop is recorded with the reason"
    );
    assert!(
        transition.unwrap().detail.contains("Mismatch")
            || transition.unwrap().detail.contains("Reference"),
        "the transition carries the dissent reason: {}",
        transition.unwrap().detail
    );

    // The change feed includes the bad node's transition.
    let feed = cp.events_since(0);
    assert!(feed
        .iter()
        .any(|e| e.subject == bad.to_hex() && e.kind == "trust-transition"));

    // Healthy audit chains → no audit-broken events.
    cp.poll_audit(mesh.node(bad), 30);
    assert!(!cp.timeline(&bad).iter().any(|e| e.kind == "audit-broken"));
}

#[tokio::test]
async fn read_api_serves_timeline_and_change_feed() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (cp, workers, _o) = observed_mesh();
    let app = api::router(Arc::new(Mutex::new(cp)));

    let resp = app
        .clone()
        .oneshot(
            Request::get("/v1/events?since=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let feed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(feed.is_array());

    let resp = app
        .oneshot(
            Request::get(format!("/v1/nodes/{}/timeline", workers[0].to_hex()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn dashboard_spa_is_served_at_root() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (cp, _w, _o) = observed_mesh();
    let app = api::router(Arc::new(Mutex::new(cp)));
    let resp = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    // It's the agreement-first console wired to the CP endpoints.
    assert!(html.contains("CITADEL"));
    assert!(html.contains("agreement first"));
    assert!(html.contains("/v1/mesh/health"));
    assert!(html.contains("/v1/events?since="));
    assert!(html.contains("/v1/audit"));
}
