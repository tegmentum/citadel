//! The control-plane read API (`monitoring-control-plane.md` §16.2, CP1) — the
//! `FleetHealthView` and node views over the verifying aggregator. Read-only;
//! it cannot affect the mesh. The write paths (§16.2, signed operator actions)
//! are CP5.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use citadel_mesh::NodeId;

use crate::{ControlPlane, ControlPlaneStore, FleetHealth, NodeView};

/// A shared, lockable control plane to serve from. The lock is held only for
/// the synchronous read; no `.await` happens under it.
pub type Shared<S> = Arc<Mutex<ControlPlane<S>>>;

/// Build the read-API router over a shared control plane.
pub fn router<S: ControlPlaneStore + 'static>(cp: Shared<S>) -> Router {
    Router::new()
        .route("/v1/mesh/health", get(mesh_health::<S>))
        .route("/v1/nodes", get(nodes::<S>))
        .route("/v1/nodes/{id}", get(node::<S>))
        .with_state(cp)
}

async fn mesh_health<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
) -> Json<FleetHealth> {
    Json(cp.lock().unwrap().fleet_health())
}

async fn nodes<S: ControlPlaneStore + 'static>(State(cp): State<Shared<S>>) -> Json<Vec<NodeView>> {
    Json(cp.lock().unwrap().nodes())
}

async fn node<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
    Path(id): Path<String>,
) -> Result<Json<NodeView>, StatusCode> {
    let nid = NodeId::from_hex(&id).ok_or(StatusCode::BAD_REQUEST)?;
    cp.lock()
        .unwrap()
        .node_view(&nid)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
