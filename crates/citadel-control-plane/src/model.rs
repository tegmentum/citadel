//! Control-plane data model.

use citadel_mesh::crypto::MeshPublicKey;
use citadel_mesh::state::{LivenessState, TrustState};
use citadel_mesh::NodeId;

/// A member's facts as the control plane knows them (from verified membership
/// gossip via the observer node). Trust is **not** stored here — it is *derived*
/// from the verified verdict history (the mesh decides trust; the CP recomputes
/// it), so the CP can never assert a trust the evidence doesn't support.
#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub id: NodeId,
    pub public_key: MeshPublicKey,
    pub role: String,
    pub liveness: LivenessState,
    /// An observer/control-plane node (excluded from fleet trust rollups).
    pub observer: bool,
    /// Latest tick we heard anything about this node.
    pub last_seen_tick: u64,
}

/// A node as presented to operators: its facts + the CP-derived trust + the
/// witness tally behind that trust (the agreement summary; CP2 fills the
/// drill-down).
#[derive(Clone, Debug, serde::Serialize)]
pub struct NodeView {
    pub id: String,
    pub role: String,
    pub liveness: String,
    /// CP-derived trust (from the verified verdicts), as a string.
    pub trust: String,
    /// `agree`/`total` verified verdicts behind the trust (0/0 = unobserved).
    pub witnesses_agree: usize,
    pub witnesses_total: usize,
    pub last_policy_revision: u64,
    pub last_seen_tick: u64,
}

/// Fleet rollup (`monitoring-control-plane.md` §6.2 / §17.1) — recomputed from
/// per-node verified state; observers are excluded.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct FleetHealth {
    pub total: usize,
    pub trusted: usize,
    pub degraded: usize,
    pub suspicious: usize,
    pub isolated: usize,
    pub probationary: usize,
    pub unknown: usize,
    /// Percentage of (non-observer) nodes currently `Trusted`.
    pub mesh_health_pct: f32,
}

/// Map a derived [`TrustState`] into the fleet histogram.
pub(crate) fn bump(h: &mut FleetHealth, trust: TrustState) {
    h.total += 1;
    match trust {
        TrustState::Trusted => h.trusted += 1,
        TrustState::Degraded => h.degraded += 1,
        TrustState::Suspicious => h.suspicious += 1,
        TrustState::Isolated | TrustState::Retired => h.isolated += 1,
        TrustState::Probationary | TrustState::ProvisionallyAdmitted => h.probationary += 1,
        TrustState::Unknown | TrustState::Untrusted => h.unknown += 1,
    }
}

pub(crate) fn trust_str(t: TrustState) -> &'static str {
    match t {
        TrustState::Untrusted => "untrusted",
        TrustState::ProvisionallyAdmitted => "provisionally-admitted",
        TrustState::Probationary => "probationary",
        TrustState::Trusted => "trusted",
        TrustState::Degraded => "degraded",
        TrustState::Suspicious => "suspicious",
        TrustState::Isolated => "isolated",
        TrustState::Retired => "retired",
        TrustState::Unknown => "unknown",
    }
}

pub(crate) fn liveness_str(l: LivenessState) -> &'static str {
    match l {
        LivenessState::Alive => "alive",
        LivenessState::Suspect => "suspect",
        LivenessState::Faulty => "faulty",
        LivenessState::Left => "left",
        LivenessState::Retired => "retired",
    }
}
