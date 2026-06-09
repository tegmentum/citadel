//! # citadel-metrics-exporter (OBS2)
//!
//! Renders Citadel's **security-state** metrics in the Prometheus text exposition
//! format from a [`MetricsSnapshot`] — a plain projection of the control plane's
//! *verified* state (the control plane builds the snapshot via
//! `ControlPlane::metrics_snapshot`, so the metrics inherit its re-verification;
//! the exporter just formats, with no dependency back on the control plane).
//!
//! Hot-path counters the control plane can't observe (latency histograms, gossip,
//! Hexis) are agent-side OTLP (roadmap OBS4).

use std::collections::BTreeMap;
use std::fmt::Write;

use citadel_otel_schema::metrics as m;

/// One node's ordinal trust, for the per-node gauge.
#[derive(Clone, Debug)]
pub struct NodeTrust {
    pub id: String,
    pub role: String,
    /// Ordinal trust code (see `citadel_otel_schema::trust_state_code`).
    pub code: i64,
}

/// A point-in-time projection of the cluster's verified security state.
#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    /// Fraction of known (non-observer) nodes currently Trusted.
    pub cluster_trust_score: f64,
    /// Known mesh peers (non-observer subjects).
    pub mesh_peer_count: u64,
    /// Nodes currently isolated/suspicious.
    pub nodes_quarantined: u64,
    /// Count of nodes per trust-state label.
    pub nodes_by_state: BTreeMap<String, u64>,
    /// Per-node ordinal trust.
    pub per_node: Vec<NodeTrust>,
    /// Verified passing/failing attestation verdicts.
    pub tpm_quote_success_total: u64,
    pub tpm_quote_failure_total: u64,
}

/// The Prometheus content type for the exposition format `render` produces.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Render the `/metrics` body from a snapshot.
pub fn render(s: &MetricsSnapshot) -> String {
    let mut out = String::new();
    gauge(
        &mut out,
        m::CLUSTER_TRUST_SCORE,
        "Fraction of known nodes currently Trusted.",
        &format!("{:.4}", s.cluster_trust_score),
    );
    gauge(
        &mut out,
        m::MESH_PEER_COUNT,
        "Mesh peers the control plane knows.",
        &s.mesh_peer_count.to_string(),
    );
    gauge(
        &mut out,
        m::NODES_QUARANTINED,
        "Nodes currently isolated or suspicious.",
        &s.nodes_quarantined.to_string(),
    );

    let _ = writeln!(
        out,
        "# HELP {} Count of nodes in each trust state.",
        m::NODES_BY_STATE
    );
    let _ = writeln!(out, "# TYPE {} gauge", m::NODES_BY_STATE);
    for (state, count) in &s.nodes_by_state {
        let _ = writeln!(out, "{}{{state=\"{state}\"}} {count}", m::NODES_BY_STATE);
    }

    let _ = writeln!(
        out,
        "# HELP {} Per-node ordinal trust level (higher = more trusted, negative = compromised).",
        m::NODE_TRUST_STATE
    );
    let _ = writeln!(out, "# TYPE {} gauge", m::NODE_TRUST_STATE);
    for n in &s.per_node {
        let _ = writeln!(
            out,
            "{}{{node=\"{}\",role=\"{}\"}} {}",
            m::NODE_TRUST_STATE,
            n.id,
            n.role,
            n.code
        );
    }

    counter(
        &mut out,
        m::TPM_QUOTE_SUCCESS_TOTAL,
        "Passing attestation verdicts the control plane has verified.",
        s.tpm_quote_success_total,
    );
    counter(
        &mut out,
        m::TPM_QUOTE_FAILURE_TOTAL,
        "Failing attestation verdicts the control plane has verified.",
        s.tpm_quote_failure_total,
    );
    out
}

fn gauge(out: &mut String, name: &str, help: &str, value: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exposition_format() {
        let mut by_state = BTreeMap::new();
        by_state.insert("trusted".to_string(), 3u64);
        by_state.insert("suspicious".to_string(), 1u64);
        let snap = MetricsSnapshot {
            cluster_trust_score: 0.75,
            mesh_peer_count: 4,
            nodes_quarantined: 1,
            nodes_by_state: by_state,
            per_node: vec![NodeTrust {
                id: "ab".repeat(32),
                role: "worker".into(),
                code: 4,
            }],
            tpm_quote_success_total: 9,
            tpm_quote_failure_total: 2,
        };
        let body = render(&snap);
        assert!(body.contains("citadel_cluster_trust_score 0.7500"));
        assert!(body.contains("# TYPE citadel_cluster_trust_score gauge"));
        assert!(body.contains("citadel_nodes_by_state{state=\"trusted\"} 3"));
        assert!(body.contains("citadel_nodes_quarantined 1"));
        assert!(body.contains("citadel_tpm_quote_failure_total 2"));
        assert!(body.contains("role=\"worker\"} 4"));
    }
}
