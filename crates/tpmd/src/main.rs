use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::Mutex;

use tpm_core::backend::{MockBackend, TpmBackend};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, TpmObject};
use tpm_core::store::Store;

struct AppState {
    store: Store,
    backend: Box<dyn TpmBackend>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let backend: Box<dyn TpmBackend> = Box::new(MockBackend::new());

    let state = Arc::new(Mutex::new(AppState { store, backend }));

    let app = Router::new()
        .route("/v1/status", get(handle_status))
        .route("/v1/keys", get(handle_list_keys))
        .route("/v1/keys", post(handle_create_key))
        .route("/v1/keys/{path}", get(handle_get_key))
        .route("/v1/objects", get(handle_list_objects))
        .route("/v1/policies", get(handle_list_policies))
        .route("/v1/health", get(handle_health))
        .with_state(state);

    let listen = std::env::var("TPMD_LISTEN").unwrap_or_else(|_| "127.0.0.1:7701".to_string());

    tracing::info!("tpmd starting on {}", listen);
    tracing::info!("store: {}", store_path.display());

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// -- Handlers --

async fn handle_status(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let status = state.backend.status().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "backend": status,
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

async fn handle_list_keys(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.lock().await;
    let objects = state.store.list_objects().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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

    let obj_path = ObjectPath::new(&req.path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("invalid path: {}", e))
    })?;

    if state.store.get_object(&obj_path).unwrap_or(None).is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("object already exists: {}", req.path),
        ));
    }

    let alg_str = req.algorithm.as_deref().unwrap_or("ecc-p256");
    let algorithm: Algorithm = alg_str.parse().map_err(|e: String| {
        (StatusCode::BAD_REQUEST, e)
    })?;

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
        .log_action("key.create", Some(&req.path), &serde_json::json!({"algorithm": alg_str, "via": "api"}))
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

    let obj_path = ObjectPath::new(&path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("invalid path: {}", e))
    })?;

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
    let objects = state.store.list_objects().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let policies = state.store.list_policies().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let status = state.backend.status().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let objects = state.store.list_objects().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let policies = state.store.list_policies().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
