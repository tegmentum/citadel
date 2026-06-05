//! HTTP integration tests for tpmd.
//!
//! These exercise the router via `tower::ServiceExt::oneshot` — no real
//! socket is opened, no TLS, no tokio runtime beyond what axum needs.
//! They cover the Phase 6 endpoints (identities, fragility, apply, graph)
//! plus a couple of sanity checks for pre-existing routes.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

use tpm_core::backend::MockBackend;
use tpm_core::store::Store;

use tpmd::{build_router, AppState};

// -- harness --

fn new_app() -> axum::Router {
    // Use SQLite in-memory so the witness_log V8 migration applies
    // and the persistent witness tests exercise the real storage path.
    let state = Arc::new(Mutex::new(AppState {
        store: Store::open_memory().expect("open in-memory sqlite store"),
        backend: Arc::new(MockBackend::new()),
    }));
    build_router(state)
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let mut req = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = app
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .expect("router error");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn send_json(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, text) = send(app, method, uri, body).await;
    let parsed = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, parsed)
}

// -- identities --

#[tokio::test]
async fn identities_list_empty_initially() {
    let app = new_app();
    let (status, body) = send_json(&app, Method::GET, "/v1/identities", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["identities"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn identities_create_and_get() {
    let app = new_app();

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/v1/identities",
        Some(json!({
            "name": "release",
            "usage": "code-signing",
            "algorithm": "ecc-p256",
            "subject": "CN=Release",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={}", body);
    assert_eq!(body["name"], "release");
    assert_eq!(body["usage"], "code-signing");
    assert!(body["key_object_id"].is_string());

    let (status, body) = send_json(&app, Method::GET, "/v1/identities/release", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "release");
    assert_eq!(body["subject"], "CN=Release");
}

#[tokio::test]
async fn identities_get_missing_returns_404() {
    let app = new_app();
    let (status, _) = send(&app, Method::GET, "/v1/identities/ghost", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn identities_rotate_sets_rotated_from() {
    let app = new_app();
    send_json(
        &app,
        Method::POST,
        "/v1/identities",
        Some(json!({"name": "rot"})),
    )
    .await;

    let (status, body) =
        send_json(&app, Method::POST, "/v1/identities/rot/rotate", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["new_key_object_id"].is_string());
    assert!(
        body["rotated_from"].as_str().is_some(),
        "rotated_from should be set after rotation"
    );
}

// -- policy fragility --

#[tokio::test]
async fn policy_fragility_high_for_pcr_0() {
    let app = new_app();

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/policies",
        Some(json!({
            "name": "fragile",
            "pcr_indices": [0, 4],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        send_json(&app, Method::GET, "/v1/policies/fragile/fragility", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["policy"], "fragile");
    assert_eq!(body["overall"], "high");
    assert!(body["per_pcr"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn policy_fragility_unknown_returns_404() {
    let app = new_app();
    let (status, _) =
        send(&app, Method::GET, "/v1/policies/ghost/fragility", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// -- apply manifest --

#[tokio::test]
async fn apply_creates_resources_from_manifest() {
    let app = new_app();

    let manifest = "apiVersion: tpm/v1\n\
         kind: Workspace\n\
         spec:\n  \
           policies:\n    \
             - name: boot\n      \
               requires:\n        \
                 pcr: [{index: 7}]\n  \
           keys:\n    \
             - path: signing/release\n      \
               algorithm: ecc-p256\n      \
               policy: boot\n";

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/v1/apply",
        Some(json!({"manifest": manifest})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body={}", body);
    assert!(body["correlation_id"].as_str().unwrap().len() > 0);
    let created = body["created"].as_array().unwrap();
    assert!(created.iter().any(|v| v == "policy:boot"));
    assert!(created.iter().any(|v| v == "key:signing/release"));
}

#[tokio::test]
async fn apply_parse_error_returns_400() {
    let app = new_app();
    let (status, _) = send(
        &app,
        Method::POST,
        "/v1/apply",
        Some(json!({"manifest": "this: is: not: valid: yaml: ["})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// -- graph --

#[tokio::test]
async fn graph_json_returns_nodes_and_edges() {
    let app = new_app();

    // Seed an identity so the graph has nodes.
    send_json(
        &app,
        Method::POST,
        "/v1/identities",
        Some(json!({"name": "g1"})),
    )
    .await;

    let (status, body) = send_json(&app, Method::GET, "/v1/graph", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["nodes"].is_array());
    assert!(body["edges"].is_array());
    assert!(
        !body["nodes"].as_array().unwrap().is_empty(),
        "graph should contain at least the seeded identity and key"
    );
}

// -- audit witness (Phase 4) --

#[tokio::test]
async fn witness_accepts_new_submission() {
    let app = new_app();
    let sub = json!({
        "stream_id": "default",
        "segment_id": 1,
        "seq_start": 1,
        "seq_end": 10,
        "checkpoint_hash_hex": "aa".repeat(32),
        "signature_hex": "bb".repeat(16),
        "signer_identity": "abc",
    });
    let (status, body) =
        send_json(&app, Method::POST, "/v1/audit/witness", Some(sub)).await;
    assert_eq!(status, StatusCode::OK, "body={}", body);
    assert_eq!(body["accepted"], true);
}

#[tokio::test]
async fn witness_rejects_equivocating_submission() {
    let app = new_app();
    let first = json!({
        "stream_id": "default",
        "segment_id": 1,
        "seq_start": 1,
        "seq_end": 10,
        "checkpoint_hash_hex": "aa".repeat(32),
        "signature_hex": "bb".repeat(16),
        "signer_identity": "abc",
    });
    send_json(&app, Method::POST, "/v1/audit/witness", Some(first)).await;

    // Same segment_id but a different checkpoint_hash ⇒ equivocation.
    let second = json!({
        "stream_id": "default",
        "segment_id": 1,
        "seq_start": 1,
        "seq_end": 10,
        "checkpoint_hash_hex": "cc".repeat(32),
        "signature_hex": "bb".repeat(16),
        "signer_identity": "abc",
    });
    let (status, _) = send(&app, Method::POST, "/v1/audit/witness", Some(second)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn witness_get_returns_latest_record() {
    let app = new_app();
    let first = json!({
        "stream_id": "default",
        "segment_id": 1,
        "seq_start": 1,
        "seq_end": 5,
        "checkpoint_hash_hex": "aa".repeat(32),
        "signature_hex": "bb".repeat(8),
        "signer_identity": "id1",
    });
    send_json(&app, Method::POST, "/v1/audit/witness", Some(first)).await;

    let (status, body) =
        send_json(&app, Method::GET, "/v1/audit/witness/default", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["segment_id"], 1);
    assert_eq!(body["checkpoint_hash_hex"], "aa".repeat(32));
}

#[tokio::test]
async fn witness_get_missing_stream_404() {
    let app = new_app();
    let (status, _) =
        send(&app, Method::GET, "/v1/audit/witness/ghost", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn witness_idempotent_republish_is_accepted() {
    let app = new_app();
    let sub = json!({
        "stream_id": "default",
        "segment_id": 3,
        "seq_start": 10,
        "seq_end": 20,
        "checkpoint_hash_hex": "cd".repeat(32),
        "signature_hex": "ef".repeat(16),
        "signer_identity": "idrepeat",
    });
    // First publish: accepted, not idempotent.
    let (status, body) =
        send_json(&app, Method::POST, "/v1/audit/witness", Some(sub.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["idempotent"], false);

    // Second publish of the exact same submission: accepted,
    // idempotent — no new row.
    let (status, body) =
        send_json(&app, Method::POST, "/v1/audit/witness", Some(sub)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["idempotent"], true);
}

#[tokio::test]
async fn witness_list_returns_full_history() {
    let app = new_app();
    for seg in 1..=3u64 {
        let sub = json!({
            "stream_id": "default",
            "segment_id": seg,
            "seq_start": (seg - 1) * 10 + 1,
            "seq_end": seg * 10,
            "checkpoint_hash_hex": format!("{:02x}", seg).repeat(32),
            "signature_hex": "ab".repeat(16),
            "signer_identity": "sid",
        });
        send_json(&app, Method::POST, "/v1/audit/witness", Some(sub)).await;
    }
    let (status, body) =
        send_json(&app, Method::GET, "/v1/audit/witness/default/list", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 3);
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["segment_id"], 1);
    assert_eq!(records[2]["segment_id"], 3);
}

#[tokio::test]
async fn graph_dot_returns_digraph() {
    let app = new_app();

    send_json(
        &app,
        Method::POST,
        "/v1/identities",
        Some(json!({"name": "g2"})),
    )
    .await;

    let (status, body) = send(&app, Method::GET, "/v1/graph?format=dot", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("digraph tpm"), "body={}", body);
    assert!(body.contains("->"));
}
