//! # citadel-metrics-exporter (OBS2)
//!
//! Renders Citadel's **security-state** metrics in the Prometheus text exposition
//! format, projecting the control plane's *verified* state (OBS1): cluster trust
//! score, per-node trust gauge, node-state counts, verified attestation
//! pass/fail, mesh peers, and quarantine. A scrape target for Prometheus or the
//! OTel Collector's Prometheus receiver.
//!
//! This is a read-only projection — the control plane re-verifies every verdict
//! before it counts, so the metrics inherit that integrity. Hot-path counters the
//! CP can't observe (latency histograms, gossip, Hexis) are agent-side OTLP
//! (roadmap OBS4).

use std::collections::BTreeMap;
use std::fmt::Write;

use citadel_control_plane::{ControlPlane, ControlPlaneStore};
use citadel_mesh::state::TrustState;
use citadel_otel_schema::{metrics as m, trust_state_code, trust_state_label};

/// Parse the control plane's lowercase trust string back to a [`TrustState`] for
/// the ordinal projection.
fn trust_from_str(s: &str) -> TrustState {
    match s {
        "trusted" => TrustState::Trusted,
        "degraded" => TrustState::Degraded,
        "probationary" => TrustState::Probationary,
        "provisionally_admitted" => TrustState::ProvisionallyAdmitted,
        "untrusted" => TrustState::Untrusted,
        "suspicious" => TrustState::Suspicious,
        "isolated" => TrustState::Isolated,
        "retired" => TrustState::Retired,
        _ => TrustState::Unknown,
    }
}

/// Render the `/metrics` body from the control plane's current verified state.
pub fn render<S: ControlPlaneStore>(cp: &ControlPlane<S>) -> String {
    let nodes = cp.nodes();
    // Exclude observer/control-plane nodes from trust accounting (they ship no
    // self-evidence) — mirror the fleet rollup.
    let subjects: Vec<_> = nodes.iter().filter(|n| n.role != "observer").collect();

    let mut by_state: BTreeMap<&str, u64> = BTreeMap::new();
    let mut trusted = 0u64;
    for n in &subjects {
        let st = trust_from_str(&n.trust);
        *by_state.entry(trust_state_label(st)).or_default() += 1;
        if matches!(st, TrustState::Trusted) {
            trusted += 1;
        }
    }
    let known = subjects.len() as u64;
    let score = if known == 0 {
        1.0
    } else {
        trusted as f64 / known as f64
    };
    let quarantined: u64 = subjects
        .iter()
        .filter(|n| {
            matches!(
                trust_from_str(&n.trust),
                TrustState::Suspicious | TrustState::Isolated
            )
        })
        .count() as u64;
    let (pass, fail, _warn) = cp.verdict_totals();

    let mut out = String::new();
    gauge(
        &mut out,
        m::CLUSTER_TRUST_SCORE,
        "Fraction of known nodes currently Trusted.",
        &format!("{score:.4}"),
    );
    gauge(
        &mut out,
        m::MESH_PEER_COUNT,
        "Mesh peers the control plane knows.",
        &known.to_string(),
    );
    gauge(
        &mut out,
        m::NODES_QUARANTINED,
        "Nodes currently isolated or suspicious.",
        &quarantined.to_string(),
    );

    let _ = writeln!(
        out,
        "# HELP {} Count of nodes in each trust state.",
        m::NODES_BY_STATE
    );
    let _ = writeln!(out, "# TYPE {} gauge", m::NODES_BY_STATE);
    for (state, count) in &by_state {
        let _ = writeln!(out, "{}{{state=\"{state}\"}} {count}", m::NODES_BY_STATE);
    }

    let _ = writeln!(
        out,
        "# HELP {} Per-node ordinal trust level (higher = more trusted, negative = compromised).",
        m::NODE_TRUST_STATE
    );
    let _ = writeln!(out, "# TYPE {} gauge", m::NODE_TRUST_STATE);
    for n in &subjects {
        let code = trust_state_code(trust_from_str(&n.trust));
        let _ = writeln!(
            out,
            "{}{{node=\"{}\",role=\"{}\"}} {code}",
            m::NODE_TRUST_STATE,
            n.id,
            n.role
        );
    }

    counter(
        &mut out,
        m::TPM_QUOTE_SUCCESS_TOTAL,
        "Passing attestation verdicts the control plane has verified.",
        pass,
    );
    counter(
        &mut out,
        m::TPM_QUOTE_FAILURE_TOTAL,
        "Failing attestation verdicts the control plane has verified.",
        fail,
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
    use citadel_control_plane::{ControlPlane, MemStore};
    use citadel_mesh::crypto::MeshKeypair;
    use citadel_mesh::membership::MemberUpdate;
    use citadel_mesh::state::LivenessState;
    use citadel_mesh::types::{AttestationResult, Verdict};
    use citadel_mesh::NodeId;

    fn member(kp: &MeshKeypair) -> MemberUpdate {
        MemberUpdate {
            node_id: NodeId(kp.public().fingerprint()),
            public_key: kp.public(),
            incarnation: 0,
            liveness: LivenessState::Alive,
            tls_cert: None,
            observer: false,
        }
    }
    fn verdict(
        verifier: &MeshKeypair,
        subject: NodeId,
        result: Verdict,
        tick: u64,
    ) -> AttestationResult {
        AttestationResult {
            subject,
            verifier: NodeId(verifier.public().fingerprint()),
            result,
            reason_codes: vec![],
            policy_revision: 5,
            confidence: 1.0,
            timestamp_tick: tick,
            signature: citadel_mesh::crypto::Signature::zero(),
        }
        .signed(verifier)
    }

    #[test]
    fn renders_trust_projection_from_verified_state() {
        let mut cp = ControlPlane::new(MemStore::new());
        let subject_kp = MeshKeypair::from_seed([1; 32]);
        let subject = NodeId(subject_kp.public().fingerprint());
        let w: Vec<MeshKeypair> = (2u8..=4).map(|s| MeshKeypair::from_seed([s; 32])).collect();
        cp.ingest_member(&member(&subject_kp), 1);
        for kp in &w {
            cp.ingest_member(&member(kp), 1);
        }
        for kp in &w {
            cp.ingest_verdict(&verdict(kp, subject, Verdict::Pass, 10));
        }

        let body = render(&cp);
        // The subject is Trusted; the witnesses have no verdicts about themselves
        // (Unknown). Score = 1 trusted / 4 known.
        assert!(body.contains("citadel_cluster_trust_score 0.2500"));
        assert!(body.contains("citadel_mesh_peer_count 4"));
        assert!(body.contains("citadel_nodes_by_state{state=\"trusted\"} 1"));
        assert!(body.contains("citadel_tpm_quote_success_total 3"));
        assert!(body.contains("citadel_nodes_quarantined 0"));
        // The subject's per-node gauge reads the Trusted ordinal (4); it's the
        // only Trusted node, so exactly one such line ends with " 4".
        assert!(body
            .lines()
            .any(|l| l.starts_with("citadel_node_trust_state{") && l.ends_with(" 4")));

        // Compromise the subject → quarantine count + failure counter move.
        for kp in &w {
            cp.ingest_verdict(&verdict(kp, subject, Verdict::Fail, 20));
        }
        let body = render(&cp);
        assert!(body.contains("citadel_nodes_quarantined 1"));
        assert!(body.contains("citadel_nodes_by_state{state=\"suspicious\"} 1"));
        assert!(body.contains("citadel_tpm_quote_failure_total 3"));
    }
}
