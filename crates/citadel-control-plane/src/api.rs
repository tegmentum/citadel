//! The control-plane HTTP API (`monitoring-control-plane.md` §16.2). The read
//! surface (CP1–CP4) is the `FleetHealthView`, node/agreement/evidence/timeline
//! views and the change feed over the verifying aggregator. The one write
//! (CP5), `POST /v1/policies`, only **validates + enqueues** an operator-signed
//! action; the host loop relays it through the observer node, and nodes adopt it
//! only if they trust the authority — the API holds no key that decides trust.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use citadel_mesh::reference::ReferenceManifest;
use citadel_mesh::NodeId;

use crate::{
    AgreementView, ControlPlane, ControlPlaneStore, EvidenceDurabilityView, FleetHealth, NodeView,
    OperatorAction, OperatorAuditEntry, TimelineEvent, WriteError,
};

#[derive(serde::Deserialize)]
pub struct SinceQuery {
    #[serde(default)]
    since: u64,
}

/// `POST /v1/policies` body: an operator-signed action + the authority-signed
/// manifest it authorizes.
#[derive(serde::Deserialize)]
pub struct PublishPolicyRequest {
    pub action: OperatorAction,
    pub manifest: ReferenceManifest,
}

/// `POST /v1/policies` reply: the accepted manifest's content id (hex).
#[derive(serde::Serialize)]
pub struct PublishPolicyReply {
    pub content_id: String,
}

fn write_status(e: WriteError) -> StatusCode {
    match e {
        // Not a registered operator → forbidden.
        WriteError::Unauthorized => StatusCode::FORBIDDEN,
        // Malformed/unverifiable request → bad request.
        WriteError::BadSignature | WriteError::TargetMismatch | WriteError::BadArtifact => {
            StatusCode::BAD_REQUEST
        }
    }
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
        .route("/v1/policies", post(publish_policy::<S>))
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

/// `POST /v1/policies` — validate + audit + **enqueue** an operator-authorized
/// policy publish. The host loop drains `drain_pending_manifests()` and relays
/// each through the observer node; this handler holds no node.
async fn publish_policy<S: ControlPlaneStore + 'static>(
    State(cp): State<Shared<S>>,
    Json(req): Json<PublishPolicyRequest>,
) -> Result<Json<PublishPolicyReply>, StatusCode> {
    let mut g = cp.lock().unwrap();
    let tick = g.current_tick();
    match g.submit_policy(&req.action, &req.manifest, tick) {
        Ok(cid) => Ok(Json(PublishPolicyReply {
            content_id: crate::hex32(&cid),
        })),
        Err(e) => Err(write_status(e)),
    }
}
