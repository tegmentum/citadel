//! Print the OTLP/HTTP traces JSON for a sample containment trace — pipe it to a
//! Collector's /v1/traces (see deploy/.../run-otlp-smoke.sh).
fn main() {
    let t = citadel_telemetry::ContainmentTrace::build(
        citadel_mesh::NodeId([42u8; 32]),
        "Q17",
        "C-9",
        "PCR7 mismatch",
        1_700_000_000_000_000_000,
        1_000_000,
    );
    println!(
        "{}",
        serde_json::to_string(&t.to_otlp_traces("citadel-local")).unwrap()
    );
}
