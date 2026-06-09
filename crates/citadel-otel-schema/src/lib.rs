//! # citadel-otel-schema (OBS1)
//!
//! The single source of truth for Citadel's observability vocabulary: the
//! Prometheus metric names and the OpenTelemetry attribute keys, defined once so
//! the two faces (Prometheus labels / OTel resource attributes) agree. Also the
//! documented projection of the categorical [`TrustState`] onto a numeric gauge
//! value so PromQL/Grafana can threshold trust.

use citadel_mesh::state::TrustState;

/// Prometheus metric names (the `citadel_*` series). Security-state metrics are a
/// projection of the control plane's verified state (OBS1).
pub mod metrics {
    /// Fraction of known nodes currently Trusted (gauge, 0..1).
    pub const CLUSTER_TRUST_SCORE: &str = "citadel_cluster_trust_score";
    /// Per-node ordinal trust level (gauge) — see [`super::trust_state_code`].
    pub const NODE_TRUST_STATE: &str = "citadel_node_trust_state";
    /// Count of nodes in each trust state (gauge), label `state`.
    pub const NODES_BY_STATE: &str = "citadel_nodes_by_state";
    /// Mesh peers the control plane knows (gauge).
    pub const MESH_PEER_COUNT: &str = "citadel_mesh_peer_count";
    /// Passing attestation verdicts the CP has verified (counter).
    pub const TPM_QUOTE_SUCCESS_TOTAL: &str = "citadel_tpm_quote_success_total";
    /// Failing attestation verdicts the CP has verified (counter).
    pub const TPM_QUOTE_FAILURE_TOTAL: &str = "citadel_tpm_quote_failure_total";
    /// Nodes currently isolated/suspicious (gauge) — containment state.
    pub const NODES_QUARANTINED: &str = "citadel_nodes_quarantined";
}

/// OpenTelemetry attribute keys attached to Citadel telemetry (OBS5 §7). The same
/// identity vocabulary used as Prometheus labels.
pub mod attr {
    pub const CLUSTER_ID: &str = "citadel.cluster.id";
    pub const NODE_ID: &str = "citadel.node.id";
    pub const QUORUM_ID: &str = "citadel.quorum.id";
    pub const ATTESTATION_ID: &str = "citadel.attestation.id";
    pub const POLICY_ID: &str = "citadel.policy.id";
    pub const CONTAINMENT_ID: &str = "citadel.containment.id";
    pub const PCR_INDEX: &str = "citadel.pcr.index";
    pub const PCR_EXPECTED: &str = "citadel.pcr.expected";
    pub const PCR_OBSERVED: &str = "citadel.pcr.observed";
    pub const QUOTE_HASH: &str = "citadel.quote.hash";
    pub const MEASUREMENT_HASH: &str = "citadel.measurement.hash";
}

/// Project the categorical [`TrustState`] onto an ordinal gauge value: higher is
/// more trusted, negative is compromised, `0` is unknown/unattested. Stable so
/// alerts can threshold (e.g. `< 0` = compromised).
pub fn trust_state_code(state: TrustState) -> i64 {
    match state {
        TrustState::Trusted => 4,
        TrustState::Degraded => 3,
        TrustState::Probationary => 2,
        TrustState::ProvisionallyAdmitted => 1,
        TrustState::Unknown | TrustState::Untrusted => 0,
        TrustState::Suspicious => -1,
        TrustState::Isolated => -2,
        TrustState::Retired => -3,
    }
}

/// The canonical lowercase label for a trust state (matches the control plane's
/// `NodeView.trust` string).
pub fn trust_state_label(state: TrustState) -> &'static str {
    match state {
        TrustState::Trusted => "trusted",
        TrustState::Degraded => "degraded",
        TrustState::Probationary => "probationary",
        TrustState::ProvisionallyAdmitted => "provisionally_admitted",
        TrustState::Unknown => "unknown",
        TrustState::Untrusted => "untrusted",
        TrustState::Suspicious => "suspicious",
        TrustState::Isolated => "isolated",
        TrustState::Retired => "retired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_codes_are_ordered_trusted_high_compromised_negative() {
        assert!(trust_state_code(TrustState::Trusted) > trust_state_code(TrustState::Probationary));
        assert!(trust_state_code(TrustState::Probationary) > trust_state_code(TrustState::Unknown));
        assert!(trust_state_code(TrustState::Suspicious) < 0);
        assert!(trust_state_code(TrustState::Isolated) < trust_state_code(TrustState::Suspicious));
    }

    #[test]
    fn labels_match_control_plane_strings() {
        assert_eq!(trust_state_label(TrustState::Trusted), "trusted");
        assert_eq!(trust_state_label(TrustState::Suspicious), "suspicious");
    }
}
