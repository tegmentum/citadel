//! # citadel-telemetry (OBS4)
//!
//! The OpenTelemetry model for Citadel's security signals — *logs explain events,
//! traces explain distributed causality*. Two first-class shapes:
//!
//! * [`SecurityEvent`] — a structured security log record (e.g. `node_quarantined`
//!   with reason + quorum), exported as an OTLP **log**.
//! * [`ContainmentTrace`] — the causal chain of a containment decision
//!   (observation → peer validation → quorum formation → containment vote →
//!   isolation command → quarantined), exported as an OTLP **trace**.
//!
//! Both carry the canonical `citadel.*` resource attributes
//! ([`citadel_otel_schema::attr`]). This crate is the model + the OTLP/HTTP JSON
//! encoding (the wire the Collector ingests) — pure and testable; wiring it into
//! the live agent hot paths + shipping to a Collector is the deployment step.

use citadel_mesh::NodeId;
use citadel_otel_schema::attr;
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic id derived from a domain seed (no randomness, so traces are
/// reproducible + testable).
fn id_from(seed: &[&[u8]], len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    for s in seed {
        h.update(s);
    }
    h.finalize().as_bytes()[..len].to_vec()
}

/// The resource attributes attached to every Citadel signal.
pub fn resource(cluster_id: &str, node: NodeId) -> Vec<(String, String)> {
    vec![
        (attr::CLUSTER_ID.to_string(), cluster_id.to_string()),
        (attr::NODE_ID.to_string(), hex(&node.0)),
    ]
}

fn otlp_attrs(kv: &[(String, String)]) -> Value {
    Value::Array(
        kv.iter()
            .map(|(k, v)| json!({ "key": k, "value": { "stringValue": v } }))
            .collect(),
    )
}

/// A structured security log record.
#[derive(Clone, Debug)]
pub struct SecurityEvent {
    /// e.g. `node_quarantined`, `attestation_failed`, `policy_rejected`.
    pub kind: String,
    pub node: NodeId,
    pub time_unix_nano: u64,
    /// `WARN` / `ERROR` / `INFO`.
    pub severity: String,
    pub attributes: Vec<(String, String)>,
}

impl SecurityEvent {
    /// A `node_quarantined` event (the canonical example from the design).
    pub fn node_quarantined(node: NodeId, reason: &str, quorum: &str, time_unix_nano: u64) -> Self {
        SecurityEvent {
            kind: "node_quarantined".to_string(),
            node,
            time_unix_nano,
            severity: "ERROR".to_string(),
            attributes: vec![
                ("citadel.reason".to_string(), reason.to_string()),
                (attr::QUORUM_ID.to_string(), quorum.to_string()),
            ],
        }
    }
}

/// Encode security events as an OTLP/HTTP `resourceLogs` payload.
pub fn to_otlp_logs(events: &[SecurityEvent], cluster_id: &str) -> Value {
    let records: Vec<Value> = events
        .iter()
        .map(|e| {
            let mut attrs = e.attributes.clone();
            attrs.push(("event.name".to_string(), e.kind.clone()));
            attrs.push((attr::NODE_ID.to_string(), hex(&e.node.0)));
            json!({
                "timeUnixNano": e.time_unix_nano.to_string(),
                "severityText": e.severity,
                "body": { "stringValue": e.kind },
                "attributes": otlp_attrs(&attrs),
            })
        })
        .collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": otlp_attrs(&[(attr::CLUSTER_ID.to_string(), cluster_id.to_string())]) },
            "scopeLogs": [{ "scope": { "name": "citadel" }, "logRecords": records }]
        }]
    })
}

/// One span in a containment trace.
#[derive(Clone, Debug)]
pub struct Span {
    pub name: String,
    pub span_id: Vec<u8>,
    pub parent_span_id: Option<Vec<u8>>,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
    pub attributes: Vec<(String, String)>,
}

/// The causal trace of a containment decision: a root span over the six ordered
/// stages from peer observation to node quarantine.
#[derive(Clone, Debug)]
pub struct ContainmentTrace {
    pub trace_id: Vec<u8>,
    pub spans: Vec<Span>,
}

/// The six ordered stages of a containment decision.
pub const CONTAINMENT_STAGES: [&str; 6] = [
    "observation",
    "peer_validation",
    "quorum_formation",
    "containment_vote",
    "isolation_command",
    "quarantined",
];

impl ContainmentTrace {
    /// Build the trace for a containment decision. `stage_nanos` is the (modelled)
    /// duration of each stage; ids are derived deterministically from
    /// `containment_id`.
    pub fn build(
        node: NodeId,
        quorum_id: &str,
        containment_id: &str,
        reason: &str,
        start_unix_nano: u64,
        stage_nanos: u64,
    ) -> Self {
        let trace_id = id_from(&[b"citadel-trace", containment_id.as_bytes()], 16);
        let root_id = id_from(&[&trace_id, b"root"], 8);
        let total = stage_nanos * CONTAINMENT_STAGES.len() as u64;
        let common = vec![
            (attr::NODE_ID.to_string(), hex(&node.0)),
            (attr::QUORUM_ID.to_string(), quorum_id.to_string()),
            (attr::CONTAINMENT_ID.to_string(), containment_id.to_string()),
        ];

        let mut spans = vec![Span {
            name: "citadel.containment".to_string(),
            span_id: root_id.clone(),
            parent_span_id: None,
            start_unix_nano,
            end_unix_nano: start_unix_nano + total,
            attributes: common.clone(),
        }];

        for (i, stage) in CONTAINMENT_STAGES.iter().enumerate() {
            let mut attrs = common.clone();
            if *stage == "quarantined" {
                attrs.push(("citadel.reason".to_string(), reason.to_string()));
            }
            spans.push(Span {
                name: format!("citadel.containment.{stage}"),
                span_id: id_from(&[&trace_id, stage.as_bytes()], 8),
                parent_span_id: Some(root_id.clone()),
                start_unix_nano: start_unix_nano + i as u64 * stage_nanos,
                end_unix_nano: start_unix_nano + (i as u64 + 1) * stage_nanos,
                attributes: attrs,
            });
        }
        ContainmentTrace { trace_id, spans }
    }

    /// Encode as an OTLP/HTTP `resourceSpans` payload.
    pub fn to_otlp_traces(&self, cluster_id: &str) -> Value {
        let trace_hex = hex(&self.trace_id);
        let spans: Vec<Value> = self
            .spans
            .iter()
            .map(|s| {
                json!({
                    "traceId": trace_hex,
                    "spanId": hex(&s.span_id),
                    "parentSpanId": s.parent_span_id.as_ref().map(|p| hex(p)).unwrap_or_default(),
                    "name": s.name,
                    "kind": 1, // SPAN_KIND_INTERNAL
                    "startTimeUnixNano": s.start_unix_nano.to_string(),
                    "endTimeUnixNano": s.end_unix_nano.to_string(),
                    "attributes": otlp_attrs(&s.attributes),
                })
            })
            .collect();
        json!({
            "resourceSpans": [{
                "resource": { "attributes": otlp_attrs(&[(attr::CLUSTER_ID.to_string(), cluster_id.to_string())]) },
                "scopeSpans": [{ "scope": { "name": "citadel" }, "spans": spans }]
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId([seed; 32])
    }

    #[test]
    fn containment_trace_is_the_causal_chain() {
        let t = ContainmentTrace::build(node(42), "Q17", "C-9", "PCR7 mismatch", 1_000, 10);
        // Root + the six ordered stages.
        assert_eq!(t.spans.len(), 7);
        assert_eq!(t.spans[0].name, "citadel.containment");
        assert!(t.spans[0].parent_span_id.is_none());
        for (i, stage) in CONTAINMENT_STAGES.iter().enumerate() {
            let s = &t.spans[i + 1];
            assert_eq!(s.name, format!("citadel.containment.{stage}"));
            assert_eq!(s.parent_span_id.as_ref(), Some(&t.spans[0].span_id));
            // Stages are time-ordered.
            assert_eq!(s.start_unix_nano, 1_000 + i as u64 * 10);
        }
        // The final stage carries the reason.
        let last = t.spans.last().unwrap();
        assert!(last
            .attributes
            .iter()
            .any(|(k, v)| k == "citadel.reason" && v == "PCR7 mismatch"));

        // Deterministic ids; OTLP shape is well-formed.
        let v = t.to_otlp_traces("citadel-local");
        let rs = &v["resourceSpans"][0];
        assert_eq!(rs["scopeSpans"][0]["spans"].as_array().unwrap().len(), 7);
        assert_eq!(rs["scopeSpans"][0]["spans"][0]["traceId"], hex(&t.trace_id));
        // Same containment id → same trace id (reproducible).
        let t2 = ContainmentTrace::build(node(42), "Q17", "C-9", "PCR7 mismatch", 9_999, 5);
        assert_eq!(t.trace_id, t2.trace_id);
    }

    #[test]
    fn security_event_log_record() {
        let ev = SecurityEvent::node_quarantined(node(7), "PCR7 mismatch", "Q17", 12345);
        let v = to_otlp_logs(&[ev], "citadel-local");
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["body"]["stringValue"], "node_quarantined");
        assert_eq!(rec["severityText"], "ERROR");
        let attrs = rec["attributes"].as_array().unwrap();
        assert!(attrs
            .iter()
            .any(|a| a["key"] == "citadel.reason" && a["value"]["stringValue"] == "PCR7 mismatch"));
        assert!(attrs
            .iter()
            .any(|a| a["key"] == "citadel.quorum.id" && a["value"]["stringValue"] == "Q17"));
    }
}
