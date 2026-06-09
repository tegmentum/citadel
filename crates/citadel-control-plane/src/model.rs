//! Control-plane data model.

use citadel_mesh::crypto::MeshPublicKey;
use citadel_mesh::state::{LivenessState, TrustState};
use citadel_mesh::NodeId;

/// A member's facts as the control plane knows them (from verified membership
/// gossip via the observer node). Trust is **not** stored here — it is *derived*
/// from the verified verdict history (the mesh decides trust; the CP recomputes
/// it), so the CP can never assert a trust the evidence doesn't support.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// Percentage of evidence records across the fleet that are reconstructable
    /// (§17.1 "Evidence durability"). `100` when no evidence has been polled.
    pub evidence_durability_pct: f32,
}

/// One verified verdict in an agreement record.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ReportView {
    pub verifier: String,
    pub verdict: String,
    pub reasons: Vec<String>,
}

/// The agreement record for a subject (`monitoring-control-plane.md` §6.1 /
/// §17.4) — the central object: which **recomputed assigned witnesses** report
/// what, agree/total, who's **silent** (assigned but no report ≠ agreement),
/// and the dissenters' reasons (expected-vs-observed). Never a bare alert.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AgreementView {
    pub subject: String,
    pub policy_revision: u64,
    /// The assigned witness set, recomputed by the CP (HRW) — not asserted.
    pub assigned: Vec<String>,
    pub quorum_threshold: usize,
    /// Assigned witnesses reporting `Pass`.
    pub agree: usize,
    /// Assigned witnesses that reported anything (agree or dissent).
    pub reported: usize,
    /// Assigned witnesses with **no** report at this revision (silence).
    pub silent: Vec<String>,
    /// Assigned witnesses reporting a non-`Pass` verdict, with their reasons.
    pub dissenters: Vec<ReportView>,
}

/// One evidence record's durability (§17.3): of `total` erasure fragments,
/// `holders_acked` distinct holders returned a verified receipt; `reconstructable`
/// iff that meets the `threshold`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DurabilityRecord {
    pub record_id: String,
    pub threshold: usize,
    pub total: usize,
    pub holders_acked: usize,
    pub reconstructable: bool,
}

/// A node's evidence durability (§17.3) — proven, not asserted: each record is
/// `reconstructable` only when ≥ threshold holders returned a verified receipt.
#[derive(Clone, Debug, serde::Serialize)]
pub struct EvidenceDurabilityView {
    pub node: String,
    pub records: Vec<DurabilityRecord>,
    pub records_total: usize,
    pub records_durable: usize,
    pub durability_pct: f32,
}

/// One entry in the forensic timeline (§17 "what changed") — every entry is
/// derived from a verified artifact (a signed verdict transition, an enrolment,
/// an audit-chain break). Ordered by `tick`; feeds both the per-subject timeline
/// and the fleet change feed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimelineEvent {
    pub tick: u64,
    pub subject: String,
    /// `enrolled` | `trust-transition` | `audit-broken`.
    pub kind: String,
    pub detail: String,
}

/// A mesh-sealed-secret release decision as presented to operators (MSS4): who
/// requested which secret, the quorum tally of its assigned witnesses, and
/// whether release was authorized. Derived from signed gossip — verifiable.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ReleaseView {
    pub secret_id: String,
    pub requester: String,
    pub quorum: usize,
    pub eligible: usize,
    pub approvals: usize,
    pub denials: usize,
    pub authorized: bool,
    pub lease_ticks: u64,
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

pub(crate) fn verdict_str(v: citadel_mesh::types::Verdict) -> &'static str {
    use citadel_mesh::types::Verdict;
    match v {
        Verdict::Pass => "pass",
        Verdict::Warn => "warn",
        Verdict::Fail => "fail",
        Verdict::Inconclusive => "inconclusive",
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
