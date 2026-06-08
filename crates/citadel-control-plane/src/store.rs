//! The control-plane store — **pluggable** behind a trait so a deployment picks
//! the backend (embedded in-memory for tests/small fleets; an external KV/TSDB
//! for scale + retention) without touching the ingestion/aggregation logic.
//!
//! The store is a verified-fact sink: it holds **member facts** (id, key, role,
//! liveness, observer) and the **verified verdict history** per subject. It does
//! no verification or aggregation itself — `ControlPlane` verifies on the way in
//! (so a backend can never be the thing that decides what's trustworthy) and
//! derives rollups on the way out.

use citadel_mesh::types::AttestationResult;
use citadel_mesh::NodeId;

use crate::model::NodeRecord;

/// Pluggable persistence for the control plane. Implementors store and return
/// data verbatim; all signature checking happens in `ControlPlane` before
/// anything reaches here.
pub trait ControlPlaneStore: Send + Sync {
    /// Insert or update a member's facts (keyed by node id).
    fn upsert_node(&mut self, node: NodeRecord);
    /// One member's facts.
    fn get_node(&self, id: &NodeId) -> Option<NodeRecord>;
    /// Every known member.
    fn all_nodes(&self) -> Vec<NodeRecord>;
    /// Append a verified verdict to a subject's history.
    fn append_verdict(&mut self, verdict: AttestationResult);
    /// All verified verdicts recorded about `subject`, in arrival order.
    fn verdicts_for(&self, subject: &NodeId) -> Vec<AttestationResult>;
}

/// In-memory store — the default backend (tests, small fleets, the read-replica
/// cache in front of a durable store).
#[derive(Default)]
pub struct MemStore {
    nodes: std::collections::HashMap<NodeId, NodeRecord>,
    verdicts: std::collections::HashMap<NodeId, Vec<AttestationResult>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ControlPlaneStore for MemStore {
    fn upsert_node(&mut self, node: NodeRecord) {
        self.nodes.insert(node.id, node);
    }
    fn get_node(&self, id: &NodeId) -> Option<NodeRecord> {
        self.nodes.get(id).cloned()
    }
    fn all_nodes(&self) -> Vec<NodeRecord> {
        self.nodes.values().cloned().collect()
    }
    fn append_verdict(&mut self, verdict: AttestationResult) {
        self.verdicts
            .entry(verdict.subject)
            .or_default()
            .push(verdict);
    }
    fn verdicts_for(&self, subject: &NodeId) -> Vec<AttestationResult> {
        self.verdicts.get(subject).cloned().unwrap_or_default()
    }
}
