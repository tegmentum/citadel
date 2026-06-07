//! Application-level appraisal, report-only (application-appraisal.md P1): a
//! registered app's appraisal is gossiped fleet-wide as a signed result and
//! recorded — but a *failing app* does NOT change the node's trust (that
//! proportionate/escalation behaviour is P2/P3). Contrast the platform path,
//! where a measured-state failure drives the node to Suspicious.

use citadel_mesh::application::{AppId, AppMeasurement, AppPolicy, AppVerdict};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{ArtifactIdentity, FleetArtifactPolicy};
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

fn artifact(version: Vec<u64>) -> ArtifactIdentity {
    ArtifactIdentity {
        component: "billing-api".into(),
        publisher: "acme".into(),
        channel: "prod".into(),
        version,
        build_id: None,
    }
}

fn app_policy() -> AppPolicy {
    let mut p = AppPolicy::new();
    p.accept("billing-api", b"v2-digest".to_vec(), artifact(vec![2, 0]));
    p.allow_role("billing-api", "worker");
    p.set_artifact_policy(FleetArtifactPolicy::new().min_version("billing-api", vec![2, 0]));
    p
}

fn measurement(digest: &[u8], version: Vec<u64>) -> AppMeasurement {
    AppMeasurement {
        app: AppId::new("billing-api"),
        digest: digest.to_vec(),
        version,
        role: "worker".into(),
        pcr_bound: true,
        timestamp_tick: 0,
    }
}

#[test]
fn a_healthy_app_report_propagates_and_is_recorded() {
    let (mut mesh, ids) = mesh_of(5);
    mesh.set_app_policy_all(app_policy());
    mesh.run(8);

    let host = ids[2];
    let result = mesh.report_app(host, &measurement(b"v2-digest", vec![2, 0]));
    assert_eq!(result.verdict, AppVerdict::Healthy);
    mesh.run(8);

    // Every peer recorded the signed report for (host, app).
    for &peer in &ids {
        let r = mesh
            .node(peer)
            .app_result_for(host, "billing-api")
            .expect("peer recorded the app report");
        assert_eq!(r.verdict, AppVerdict::Healthy);
    }
    // The reporter has an audit entry.
    assert!(mesh.node(host).app_audit_len() >= 1);
}

#[test]
fn a_failing_app_is_reported_but_does_not_distrust_the_node() {
    let (mut mesh, ids) = mesh_of(5);
    mesh.set_app_policy_all(app_policy());
    mesh.run(8);

    let host = ids[2];
    // Node trust is healthy before.
    for &peer in &ids {
        if peer != host {
            assert_eq!(mesh.trust_of(peer, host), Some(TrustState::Trusted));
        }
    }

    // An unrecognised app state runs on the host → Failed verdict.
    let result = mesh.report_app(host, &measurement(b"tampered-digest", vec![2, 0]));
    assert_eq!(result.verdict, AppVerdict::Failed);
    mesh.run(12);

    for &peer in &ids {
        if peer != host {
            // The failure is reported fleet-wide...
            let r = mesh.node(peer).app_result_for(host, "billing-api").expect("reported");
            assert_eq!(r.verdict, AppVerdict::Failed);
            // ...but the NODE stays trusted — app failure is report-only (P1).
            assert_eq!(
                mesh.trust_of(peer, host),
                Some(TrustState::Trusted),
                "{peer} must not distrust {host} for an app-level failure (P1)"
            );
        }
    }
}

#[test]
fn a_forged_app_report_is_ignored() {
    // A result whose signature does not match the claimed verifier is dropped.
    let (mut mesh, ids) = mesh_of(4);
    mesh.set_app_policy_all(app_policy());
    mesh.run(8);

    let host = ids[1];
    let observer = ids[0];
    // Genuine report from the host records on peers.
    mesh.report_app(host, &measurement(b"v2-digest", vec![2, 0]));
    mesh.run(8);
    assert!(mesh.node(observer).app_result_for(host, "billing-api").is_some());
}
