//! The control-plane read API (`monitoring-control-plane.md` §16.2, CP1) — the
//! `FleetHealthView` and node views over the verifying aggregator. Read-only;
//! it cannot affect the mesh. The write paths (§16.2, signed operator actions)
//! are CP5.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use citadel_mesh::NodeId;

use crate::{
    AgreementView, ControlPlane, ControlPlaneStore, EvidenceDurabilityView, FleetHealth, NodeView,
    OperatorAuditEntry, TimelineEvent,
};

#[derive(serde::Deserialize)]
pub struct SinceQuery {
    #[serde(default)]
    since: u64,
}

/// A shared, lockable control plane to serve from. The lock is held only for
/// the synchronous read; no `.await` happens under it.
pub type Shared<S> = Arc<Mutex<ControlPlane<S>>>;

/// Build the read-API router over a shared control plane.
pub fn router<S: ControlPlaneStore + 'static>(cp: Shared<S>) -> Router {
    Router::new()
        .route("/v1/mesh/health", get(mesh_health::<S>))
        .route("/v1/nodes", get(nodes::<S>))
        .route("/v1/nodes/{id}", get(node::<S>))
        .route("/v1/nodes/{id}/agreement", get(agreement::<S>))
        .route("/v1/nodes/{id}/evidence", get(evidence::<S>))
        .route("/v1/nodes/{id}/timeline", get(timeline::<S>))
        .route("/v1/events", get(events::<S>))
        .route("/v1/audit", get(operator_audit::<S>))
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

async fn agreement<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
    Path(id): Path<String>,
) -> Result<Json<AgreementView>, StatusCode> {
    let nid = NodeId::from_hex(&id).ok_or(StatusCode::BAD_REQUEST)?;
    cp.lock()
        .unwrap()
        .agreement(&nid)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn evidence<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
    Path(id): Path<String>,
) -> Result<Json<EvidenceDurabilityView>, StatusCode> {
    let nid = NodeId::from_hex(&id).ok_or(StatusCode::BAD_REQUEST)?;
    cp.lock()
        .unwrap()
        .evidence_view(&nid)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn timeline<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<TimelineEvent>>, StatusCode> {
    let nid = NodeId::from_hex(&id).ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Json(cp.lock().unwrap().timeline(&nid)))
}

async fn events<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
    Query(q): Query<SinceQuery>,
) -> Json<Vec<TimelineEvent>> {
    Json(cp.lock().unwrap().events_since(q.since))
}

async fn operator_audit<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
) -> Json<Vec<OperatorAuditEntry>> {
    Json(cp.lock().unwrap().operator_audit())
}
