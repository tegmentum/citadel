//! tpmd — TPM operator HTTP daemon.
//!
//! The `main.rs` binary is a thin wrapper around [`run`], which opens the
//! store, constructs the backend, and serves the HTTP API over either
//! plain TCP or TLS depending on environment variables.
//!
//! Integration tests construct a `Router` directly via [`build_router`]
//! and drive it with `tower::ServiceExt::oneshot`, so the full HTTP
//! surface is exercised without opening a socket.

use std::sync::Arc;

pub mod tls;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::Mutex;

use tpm_core::backend::{MockBackend, TpmBackend};
use tpm_core::model::{
    Algorithm, ApprovalRequest, ApprovalStatus, ObjectKind, ObjectPath, TpmObject,
};
use tpm_core::store::Store;

/// Server state shared by all HTTP handlers.
///
/// Wrapped in `Arc<Mutex<_>>` by callers so that concurrent requests
/// serialize access to the store and backend.
pub struct AppState {
    pub store: Store,
    /// Shared so the same TPM key custodian backs both the HTTP API and the
    /// TLS layer (see [`tls`]).
    pub backend: Arc<dyn TpmBackend>,
}

/// Build the full HTTP router, including API-key middleware.
///
/// Integration tests call this directly. Production code calls [`run`].
pub fn build_router(state: Arc<Mutex<AppState>>) -> Router {
    Router::new()
        .route("/v1/status", get(handle_status))
        .route("/v1/keys", get(handle_list_keys))
        .route("/v1/keys", post(handle_create_key))
        .route("/v1/keys/{*path}", get(handle_get_key))
        .route("/v1/sign/{*path}", post(handle_sign))
        .route("/v1/delete/{*path}", post(handle_delete_key))
        .route("/v1/objects", get(handle_list_objects))
        .route("/v1/policies", get(handle_list_policies))
        .route("/v1/policies", post(handle_create_policy))
        .route(
            "/v1/policies/{name}/fragility",
            get(handle_policy_fragility),
        )
        .route("/v1/secrets", get(handle_list_secrets))
        .route("/v1/audit", get(handle_audit_log))
        .route("/v1/health", get(handle_health))
        .route("/v1/approvals", get(handle_list_approvals))
        .route("/v1/approvals", post(handle_request_approval))
        .route("/v1/approvals/{id}/approve", post(handle_approve))
        .route("/v1/approvals/{id}/deny", post(handle_deny))
        .route("/v1/identities", get(handle_list_identities))
        .route("/v1/identities", post(handle_create_identity))
        .route("/v1/identities/{name}", get(handle_get_identity))
        .route(
            "/v1/identities/{name}/rotate",
            post(handle_rotate_identity),
        )
        .route("/v1/apply", post(handle_apply))
        .route("/v1/graph", get(handle_graph))
        .route("/v1/audit/witness", post(handle_audit_witness))
        .route("/v1/audit/witness/{stream_id}", get(handle_audit_witness_get))
        .route("/v1/audit/witness/{stream_id}/list", get(handle_audit_witness_list))
        .layer(axum::middleware::from_fn(check_api_key))
        .with_state(state)
}

fn default_store_path() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(dir).join("tpm").join("tpmd.db")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("tpm")
            .join("tpmd.db")
    } else {
        std::path::PathBuf::from("tpmd.db")
    }
}

/// Run the tpmd server until terminated.
///
/// Reads `TPM_STORE_PATH`, `TPMD_LISTEN`, `TPMD_TLS_CERT`, `TPMD_TLS_KEY`,
/// and `TPMD_TLS_CA` from the environment.
pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tpmd=info".into()),
        )
        .init();

    let store_path = std::env::var("TPM_STORE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| default_store_path());

    let store = Store::open(&store_path)?;
    let backend: Arc<dyn TpmBackend> = Arc::new(MockBackend::new());
    // The TLS layer (when a TPM-backed identity is configured) signs the
    // handshake with the same backend the API uses — one key custodian.
    let tls_backend = backend.clone();

    // Open a second store handle for the TLS setup before `store` is moved
    // into the shared state (both point at the same database).
    let tls_store = if std::env::var("TPMD_TLS_IDENTITY").is_ok() {
        Some(Store::open(&store_path)?)
    } else {
        None
    };

    let state = Arc::new(Mutex::new(AppState { store, backend }));
    let app = build_router(state);

    let listen = std::env::var("TPMD_LISTEN").unwrap_or_else(|_| "127.0.0.1:7701".to_string());

    tracing::info!("tpmd starting on {}", listen);
    tracing::info!("store: {}", store_path.display());

    // TLS, in order of preference:
    //   1. TPMD_TLS_IDENTITY — the server key lives in the TPM (no private
    //      key on disk); the certificate comes from the identity's stored
    //      certificate_pem or a TPMD_TLS_CERT file.
    //   2. TPMD_TLS_CERT + TPMD_TLS_KEY — a classic on-disk PEM keypair.
    //   3. plain TCP.
    let tls_identity = std::env::var("TPMD_TLS_IDENTITY").ok();
    let tls_cert = std::env::var("TPMD_TLS_CERT").ok();
    let tls_key = std::env::var("TPMD_TLS_KEY").ok();

    match (tls_identity, tls_cert, tls_key) {
        (Some(identity_name), _, _) => {
            let store = tls_store.expect("opened when TPMD_TLS_IDENTITY is set");
            let cert_pem = resolve_tls_cert(&store, &identity_name)?;
            tracing::info!(
                "TLS enabled: server key held in the TPM via identity '{}'",
                identity_name
            );
            let config =
                tls::server_config_from_identity(&store, tls_backend, &identity_name, &cert_pem)?;
            let addr: std::net::SocketAddr = listen.parse()?;
            axum_server::bind_rustls(addr, axum_server::tls_rustls::RustlsConfig::from_config(config))
                .serve(app.into_make_service())
                .await?;
        }
        (None, Some(cert_path), Some(key_path)) => {
            tracing::info!("TLS enabled: cert={}, key={} (on-disk key)", cert_path, key_path);

            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &cert_path,
                &key_path,
            )
            .await?;

            if let Ok(ca_path) = std::env::var("TPMD_TLS_CA") {
                tracing::info!("mTLS enabled: ca={}", ca_path);
            }

            let addr: std::net::SocketAddr = listen.parse()?;
            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            let _ = tls_backend;
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

/// Resolve the certificate (PEM) presented for a TPM-backed TLS identity:
/// the identity's stored `certificate_pem`, else a `TPMD_TLS_CERT` file.
fn resolve_tls_cert(store: &Store, identity_name: &str) -> anyhow::Result<String> {
    if let Some(id) = store.get_identity(identity_name)? {
        if let Some(pem) = id.certificate_pem {
            return Ok(pem);
        }
    }
    if let Ok(path) = std::env::var("TPMD_TLS_CERT") {
        return std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading TPMD_TLS_CERT {path}: {e}"));
    }
    anyhow::bail!(
        "TLS identity '{identity_name}' has no certificate; store one with \
         `tpm identity` certificate import, or set TPMD_TLS_CERT to a PEM file"
    )
}

// -- Handlers --

async fn handle_status(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let status = state
        .backend
        .status()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "backend": status,
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

async fn handle_list_keys(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let objects = state
        .store
        .list_objects()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let keys: Vec<serde_json::Value> = objects
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
            )
        })
        .map(|o| {
            serde_json::json!({
                "path": o.path.to_string(),
                "kind": o.kind.to_string(),
                "algorithm": o.algorithm.to_string(),
                "created_at": o.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "keys": keys })))
}

#[derive(Deserialize)]
struct CreateKeyRequest {
    path: String,
    algorithm: Option<String>,
}

async fn handle_create_key(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;

    let obj_path = ObjectPath::new(&req.path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid path: {}", e)))?;

    if state.store.get_object(&obj_path).unwrap_or(None).is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("object already exists: {}", req.path),
        ));
    }

    let alg_str = req.algorithm.as_deref().unwrap_or("ecc-p256");
    let algorithm: Algorithm = alg_str
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, e))?;

    let handle = state
        .backend
        .create_key(algorithm, &obj_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let obj = TpmObject {
        id: uuid::Uuid::new_v4(),
        path: obj_path,
        kind: ObjectKind::SigningKey,
        algorithm,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: chrono::Utc::now(),
        metadata: serde_json::json!({}),
    };

    state
        .store
        .insert_object(&obj)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action(
            "key.create",
            Some(&req.path),
            &serde_json::json!({"algorithm": alg_str, "via": "api"}),
        )
        .ok();

    Ok(Json(serde_json::json!({
        "path": req.path,
        "id": obj.id.to_string(),
        "algorithm": algorithm.to_string(),
    })))
}

async fn handle_get_key(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;

    let obj_path = ObjectPath::new(&path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid path: {}", e)))?;

    let obj = state
        .store
        .get_object(&obj_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, format!("not found: {}", path)))?;

    Ok(Json(serde_json::json!({
        "path": obj.path.to_string(),
        "id": obj.id.to_string(),
        "kind": obj.kind.to_string(),
        "algorithm": obj.algorithm.to_string(),
        "has_policy": obj.policy_id.is_some(),
        "created_at": obj.created_at.to_rfc3339(),
    })))
}

async fn handle_list_objects(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let objects = state
        .store
        .list_objects()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<serde_json::Value> = objects
        .iter()
        .map(|o| {
            serde_json::json!({
                "path": o.path.to_string(),
                "kind": o.kind.to_string(),
                "algorithm": o.algorithm.to_string(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "objects": items })))
}

async fn handle_list_policies(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let policies = state
        .store
        .list_policies()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<serde_json::Value> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "rule_count": p.rules.len(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "policies": items })))
}

async fn handle_health(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let status = state
        .backend
        .status()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let objects = state
        .store
        .list_objects()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let policies = state
        .store
        .list_policies()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let profile = state.store.get_active_profile().ok().flatten();

    let mut score: i32 = 100;
    let mut issues: Vec<String> = Vec::new();

    if !status.available {
        score -= 40;
        issues.push("backend unavailable".to_string());
    }
    if profile.is_none() {
        score -= 10;
        issues.push("no active profile".to_string());
    }

    let score = score.max(0) as u8;
    let posture = match score {
        90..=100 => "healthy",
        70..=89 => "degraded",
        40..=69 => "warning",
        _ => "critical",
    };

    Ok(Json(serde_json::json!({
        "posture": posture,
        "score": score,
        "issues": issues,
        "objects": objects.len(),
        "policies": policies.len(),
    })))
}

// -- Signing --

#[derive(Deserialize)]
struct SignRequest {
    /// Hex-encoded data to sign.
    data_hex: String,
}

async fn handle_sign(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let obj_path =
        ObjectPath::new(&path).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let obj = state
        .store
        .get_object(&obj_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, format!("not found: {}", path)))?;

    let handle_blob = obj
        .handle_blob
        .ok_or((StatusCode::BAD_REQUEST, "key has no handle".to_string()))?;

    let handle = tpm_core::backend::KeyHandle {
        id: handle_blob,
        path: path.clone(),
    };

    let data: Vec<u8> = (0..req.data_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&req.data_hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {}", e)))?;

    let signature = state
        .backend
        .sign(&handle, &data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action(
            "key.sign",
            Some(&path),
            &serde_json::json!({"via": "api", "data_len": data.len()}),
        )
        .ok();

    let sig_hex: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(Json(serde_json::json!({
        "key": path,
        "signature_hex": sig_hex,
    })))
}

// -- Delete key --

async fn handle_delete_key(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let obj_path =
        ObjectPath::new(&path).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    if !state
        .store
        .delete_object(&obj_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        return Err((StatusCode::NOT_FOUND, format!("not found: {}", path)));
    }

    state
        .store
        .log_action(
            "key.delete",
            Some(&path),
            &serde_json::json!({"via": "api"}),
        )
        .ok();

    Ok(Json(serde_json::json!({"deleted": path})))
}

// -- Create policy --

#[derive(Deserialize)]
struct CreatePolicyRequest {
    name: String,
    pcr_indices: Option<Vec<u32>>,
    pcr_bank: Option<String>,
    require_password: Option<bool>,
}

async fn handle_create_policy(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;

    if state.store.get_policy(&req.name).unwrap_or(None).is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("policy already exists: {}", req.name),
        ));
    }

    let mut rules = Vec::new();
    if let Some(indices) = &req.pcr_indices {
        if !indices.is_empty() {
            rules.push(tpm_core::model::PolicyRule::PcrMatch {
                bank: req.pcr_bank.clone().unwrap_or("sha256".to_string()),
                indices: indices.clone(),
            });
        }
    }
    if req.require_password.unwrap_or(false) {
        rules.push(tpm_core::model::PolicyRule::Password);
    }

    let policy = tpm_core::model::Policy {
        id: uuid::Uuid::new_v4(),
        name: req.name.clone(),
        rules,
    };

    state
        .store
        .insert_policy(&policy)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action(
            "policy.create",
            None,
            &serde_json::json!({"name": &req.name, "via": "api"}),
        )
        .ok();

    Ok(Json(serde_json::json!({
        "name": req.name,
        "id": policy.id.to_string(),
        "rule_count": policy.rules.len(),
    })))
}

// -- List secrets --

async fn handle_list_secrets(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let objects = state
        .store
        .list_objects()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let secrets: Vec<serde_json::Value> = objects
        .iter()
        .filter(|o| o.kind == ObjectKind::SealedBlob)
        .map(|o| {
            serde_json::json!({
                "path": o.path.to_string(),
                "has_policy": o.policy_id.is_some(),
                "created_at": o.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "secrets": secrets })))
}

// -- Audit log --

async fn handle_audit_log(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let entries = state
        .store
        .list_audit_log(None, None, 50)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "entries": entries })))
}

// -- Approval workflows --

async fn handle_list_approvals(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let approvals = state
        .store
        .list_approvals()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<serde_json::Value> = approvals
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id.to_string(),
                "operation": a.operation,
                "target": a.target,
                "requester": a.requester,
                "status": a.status,
                "created_at": a.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "approvals": items })))
}

#[derive(Deserialize)]
struct ApprovalReq {
    operation: String,
    target: Option<String>,
    requester: String,
    reason: Option<String>,
}

async fn handle_request_approval(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<ApprovalReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;

    let approval = ApprovalRequest {
        id: uuid::Uuid::new_v4(),
        operation: req.operation.clone(),
        target: req.target.clone(),
        requester: req.requester.clone(),
        reason: req.reason,
        status: ApprovalStatus::Pending,
        created_at: chrono::Utc::now(),
        resolved_at: None,
        resolved_by: None,
    };

    let id = approval.id;
    state
        .store
        .insert_approval(&approval)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action(
            "approval.request",
            req.target.as_deref(),
            &serde_json::json!({
                "id": id.to_string(),
                "operation": req.operation,
                "requester": req.requester,
            }),
        )
        .ok();

    Ok(Json(serde_json::json!({
        "id": id.to_string(),
        "status": "pending",
    })))
}

async fn handle_approve(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let uuid: uuid::Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid UUID".to_string()))?;

    let approval = state
        .store
        .get_approval(&uuid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "approval not found".to_string()))?;

    if approval.status != ApprovalStatus::Pending {
        return Err((
            StatusCode::CONFLICT,
            format!("approval already {}", approval.status),
        ));
    }

    state
        .store
        .update_approval_status(&uuid, ApprovalStatus::Approved, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action("approval.approve", None, &serde_json::json!({"id": id}))
        .ok();

    Ok(Json(serde_json::json!({"id": id, "status": "approved"})))
}

async fn handle_deny(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let uuid: uuid::Uuid = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid UUID".to_string()))?;

    let approval = state
        .store
        .get_approval(&uuid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "approval not found".to_string()))?;

    if approval.status != ApprovalStatus::Pending {
        return Err((
            StatusCode::CONFLICT,
            format!("approval already {}", approval.status),
        ));
    }

    state
        .store
        .update_approval_status(&uuid, ApprovalStatus::Denied, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action("approval.deny", None, &serde_json::json!({"id": id}))
        .ok();

    Ok(Json(serde_json::json!({"id": id, "status": "denied"})))
}

// -- Identity endpoints (Phase 4) --

async fn handle_list_identities(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let identities = state
        .store
        .list_identities()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<serde_json::Value> = identities
        .iter()
        .map(|i| {
            serde_json::json!({
                "name": i.name,
                "id": i.id.to_string(),
                "usage": i.usage.to_string(),
                "key_object_id": i.key_object_id.to_string(),
                "subject": i.subject,
                "certificate_present": i.certificate_pem.is_some(),
                "created_at": i.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "identities": items })))
}

async fn handle_get_identity(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let ident = state
        .store
        .get_identity(&name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("identity not found: {}", name),
        ))?;
    Ok(Json(serde_json::json!({
        "name": ident.name,
        "id": ident.id.to_string(),
        "usage": ident.usage.to_string(),
        "key_object_id": ident.key_object_id.to_string(),
        "policy_id": ident.policy_id.map(|p| p.to_string()),
        "subject": ident.subject,
        "certificate_present": ident.certificate_pem.is_some(),
        "created_at": ident.created_at.to_rfc3339(),
        "rotated_from": ident.rotated_from.map(|r| r.to_string()),
    })))
}

#[derive(Deserialize)]
struct CreateIdentityRequest {
    name: String,
    usage: Option<String>,
    algorithm: Option<String>,
    policy: Option<String>,
    subject: Option<String>,
}

async fn handle_create_identity(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let usage_str = req.usage.as_deref().unwrap_or("generic");
    let usage: tpm_core::model::IdentityUsage = usage_str
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, e))?;
    let algorithm = req.algorithm.as_deref().unwrap_or("ecc-p256");

    let ident = tpm_core::service::init_identity(
        &state.store,
        state.backend.as_ref(),
        tpm_core::service::InitIdentitySpec {
            name: &req.name,
            usage,
            algorithm,
            policy_name: req.policy.as_deref(),
            subject: req.subject.as_deref(),
            key_path: None,
        },
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "name": ident.name,
        "id": ident.id.to_string(),
        "usage": ident.usage.to_string(),
        "key_object_id": ident.key_object_id.to_string(),
    })))
}

async fn handle_rotate_identity(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let ident =
        tpm_core::service::rotate_identity(&state.store, state.backend.as_ref(), &name)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "name": ident.name,
        "new_key_object_id": ident.key_object_id.to_string(),
        "rotated_from": ident.rotated_from.map(|r| r.to_string()),
    })))
}

// -- Policy fragility --

async fn handle_policy_fragility(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let policy = state
        .store
        .get_policy(&name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, format!("policy not found: {}", name)))?;
    let report = tpm_core::service::rate_policy(&policy);
    Ok(Json(serde_json::json!({
        "policy": name,
        "overall": report.overall.to_string(),
        "per_pcr": report.per_pcr.iter().map(|p| serde_json::json!({
            "bank": p.bank,
            "index": p.index,
            "rating": p.rating.to_string(),
            "reason": p.reason,
        })).collect::<Vec<_>>(),
        "notes": report.notes,
    })))
}

// -- Apply manifest --

#[derive(Deserialize)]
struct ApplyRequest {
    manifest: String,
    #[serde(default)]
    force: bool,
}

async fn handle_apply(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<ApplyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let manifest = tpm_core::policy::Manifest::from_yaml(&req.manifest)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("manifest parse: {}", e)))?;

    let issues = manifest.validate();
    if !issues.is_empty() {
        let joined = issues
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err((StatusCode::BAD_REQUEST, joined));
    }

    let report = tpm_core::service::apply_manifest(
        &state.store,
        state.backend.as_ref(),
        &manifest,
        req.force,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "correlation_id": report.correlation_id,
        "created": report.created,
        "updated": report.updated,
        "warnings": report.warnings,
        "errors": report.errors,
    })))
}

// -- Graph --

async fn handle_graph(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    use axum::response::IntoResponse;
    let state = state.lock().await;
    let graph = tpm_core::service::build_graph(&state.store)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let format = params.get("format").map(String::as_str).unwrap_or("json");
    match format {
        "dot" => {
            use tpm_core::output::format::DotRenderable;
            let dot = graph.render_dot();
            Ok(([("content-type", "text/vnd.graphviz")], dot).into_response())
        }
        _ => Ok(Json(serde_json::to_value(&graph).unwrap()).into_response()),
    }
}

// -- Audit witness (Phase 4) --

async fn handle_audit_witness(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<tpm_core::secure_log::witness::WitnessSubmission>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    // Equivocation check: consult the *latest* witness log row for
    // this stream. Persistent variant: survives tpmd restarts, can
    // be replayed for forensic review later.
    if let Some(prev) = state
        .store
        .witness_log_latest(&req.stream_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        if prev.segment_id > req.segment_id {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "rejected: previously witnessed segment {} for stream {}, got {}",
                    prev.segment_id, req.stream_id, req.segment_id
                ),
            ));
        }
        if prev.segment_id == req.segment_id
            && prev.checkpoint_hash_hex != req.checkpoint_hash_hex
        {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "equivocation: segment {} for stream {} previously witnessed with hash {}, now {}",
                    req.segment_id,
                    req.stream_id,
                    prev.checkpoint_hash_hex,
                    req.checkpoint_hash_hex
                ),
            ));
        }
        // Idempotent republish: same segment_id AND same hash — no
        // new row needed, just report acceptance.
        if prev.segment_id == req.segment_id
            && prev.checkpoint_hash_hex == req.checkpoint_hash_hex
        {
            return Ok(Json(serde_json::json!({
                "stream_id": req.stream_id,
                "segment_id": req.segment_id,
                "checkpoint_hash_hex": req.checkpoint_hash_hex,
                "accepted": true,
                "idempotent": true,
                "received_at_rfc3339": prev.received_at_rfc3339,
            })));
        }
    }

    // Append to the persistent witness log.
    let row = tpm_core::store::WitnessLogRow {
        id: None,
        stream_id: req.stream_id.clone(),
        segment_id: req.segment_id,
        seq_start: req.seq_start,
        seq_end: req.seq_end,
        checkpoint_hash_hex: req.checkpoint_hash_hex.clone(),
        signature_hex: req.signature_hex.clone(),
        signer_identity: req.signer_identity.clone(),
        received_at_rfc3339: now.clone(),
    };
    state
        .store
        .witness_log_insert(&row)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .log_action(
            "audit.witness.accept",
            Some(&req.stream_id),
            &serde_json::json!({
                "segment_id": req.segment_id,
                "checkpoint_hash_hex": req.checkpoint_hash_hex,
                "signer_identity": req.signer_identity,
            }),
        )
        .ok();

    Ok(Json(serde_json::json!({
        "stream_id": req.stream_id,
        "segment_id": req.segment_id,
        "checkpoint_hash_hex": req.checkpoint_hash_hex,
        "accepted": true,
        "idempotent": false,
        "received_at_rfc3339": now,
    })))
}

async fn handle_audit_witness_get(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(stream_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    match state
        .store
        .witness_log_latest(&stream_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        Some(row) => Ok(Json(serde_json::json!({
            "stream_id": row.stream_id,
            "segment_id": row.segment_id,
            "seq_start": row.seq_start,
            "seq_end": row.seq_end,
            "checkpoint_hash_hex": row.checkpoint_hash_hex,
            "signature_hex": row.signature_hex,
            "signer_identity": row.signer_identity,
            "received_at_rfc3339": row.received_at_rfc3339,
        }))),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no witness record for stream '{}'", stream_id),
        )),
    }
}

/// List every witness receipt for a stream (replay / forensic).
async fn handle_audit_witness_list(
    State(state): State<Arc<Mutex<AppState>>>,
    axum::extract::Path(stream_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let state = state.lock().await;
    let rows = state
        .store
        .witness_log_list(&stream_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "stream_id": stream_id,
        "count": rows.len(),
        "records": rows,
    })))
}

// -- API key auth middleware --

/// Simple API key authentication via X-API-Key header.
/// Set TPMD_API_KEY env var to require authentication.
async fn check_api_key(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    if let Ok(required_key) = std::env::var("TPMD_API_KEY") {
        let provided = req
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != required_key {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(req).await)
}
