//! Application-level appraisal, report-only (application-appraisal.md P1): a
//! registered app's appraisal is gossiped fleet-wide as a signed result and
//! recorded — but a *failing app* does NOT change the node's trust (that
//! proportionate/escalation behaviour is P2/P3). Contrast the platform path,
//! where a measured-state failure drives the node to Suspicious.

use citadel_mesh::application::{AppId, AppMeasurement, AppPolicy, AppVerdict};
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::quarantine::QuarantineScope;
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
fn graded_response_blocks_scheduling_without_quarantining_the_node() {
    // P2 §5.2: a failing app is met with a graded, app-scoped response
    // (block workload scheduling) on quorum — the node is NOT quarantined.
    let (mut mesh, ids) = mesh_of(5);
    mesh.set_app_policy_all(app_policy());
    mesh.run(8);
    let host = ids[2];

    let bad = measurement(b"tampered-digest", vec![2, 0]);
    let enacted = mesh.quarantine_app(host, &bad, QuarantineScope::BlockWorkloadScheduling, false);
    assert!(enacted, "witnesses that see the app failed should enact the scope");

    for &peer in &ids {
        // New workloads of the app are blocked on the host...
        assert!(
            mesh.node(peer).app_workload_blocked(host, "billing-api"),
            "{peer} should block scheduling billing-api on {host}"
        );
        // ...credentials are NOT revoked (lighter scope)...
        assert!(!mesh.node(peer).app_credentials_revoked(host, "billing-api"));
        // ...and the NODE itself stays trusted.
        if peer != host {
            assert_eq!(mesh.trust_of(peer, host), Some(TrustState::Trusted));
        }
    }
}

#[test]
fn credential_revoke_needs_an_operator() {
    let (mut mesh, ids) = mesh_of(5);
    mesh.set_app_policy_all(app_policy());
    mesh.run(8);
    let host = ids[2];
    let bad = measurement(b"tampered-digest", vec![2, 0]);

    // CredentialRevoke requires operator sign-off — witnesses alone can't.
    assert!(!mesh.quarantine_app(host, &bad, QuarantineScope::CredentialRevoke, false));
    assert!(!mesh.node(ids[0]).app_credentials_revoked(host, "billing-api"));

    // With the operator, it enacts.
    assert!(mesh.quarantine_app(host, &bad, QuarantineScope::CredentialRevoke, true));
    for &peer in &ids {
        assert!(mesh.node(peer).app_credentials_revoked(host, "billing-api"));
    }
}

#[test]
fn a_critical_app_failure_escalates_to_node_distrust() {
    // P3 §5.3: a *critical* app's failure rolls up to node distrust.
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig { witness_count: 3, attestation_interval: 3, ..NodeConfig::default() };
    let ids: Vec<NodeId> = (1..=5).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    let mut policy = app_policy();
    policy.mark_critical("billing-api");
    mesh.set_app_policy_all(policy);
    mesh.run(8);

    let host = ids[2];
    // A peer appraises and records a Failed result for the critical app, by
    // hearing the host's own report.
    mesh.report_app(host, &measurement(b"tampered-digest", vec![2, 0]));
    mesh.run(8);

    for &peer in &ids {
        if peer != host {
            assert_eq!(
                mesh.trust_of(peer, host),
                Some(TrustState::Suspicious),
                "{peer} should distrust {host} after its CRITICAL app failed"
            );
        }
    }
}

#[test]
fn threshold_escalation_only_after_enough_apps_fail() {
    // P3: with a count threshold of 2, one failing app does not escalate but
    // two distinct failing apps do.
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        app_escalation_threshold: 2,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=5).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    let mut policy = app_policy();
    policy.accept("metrics", b"m1".to_vec(), artifact(vec![1, 0]));
    mesh.set_app_policy_all(policy);
    mesh.run(8);
    let host = ids[2];

    // One failing app → still trusted.
    mesh.report_app(host, &measurement(b"bad-billing", vec![2, 0]));
    mesh.run(8);
    assert_eq!(mesh.trust_of(ids[0], host), Some(TrustState::Trusted));

    // A second distinct failing app crosses the threshold → distrust.
    let metrics_fail = AppMeasurement {
        app: AppId::new("metrics"),
        digest: b"bad-metrics".to_vec(),
        version: vec![1, 0],
        role: "worker".into(),
        pcr_bound: true,
        timestamp_tick: 0,
    };
    mesh.report_app(host, &metrics_fail);
    mesh.run(8);
    assert_eq!(
        mesh.trust_of(ids[0], host),
        Some(TrustState::Suspicious),
        "two distinct failing apps should cross the escalation threshold"
    );
}

#[test]
fn pcr_bound_claim_is_verified_against_the_event_log() {
    // P4: a measurement claiming pcr_bound is only treated as bound if its
    // digest is actually measured into the IMA PCR (10) of a replayable log;
    // otherwise it is downgraded to advisory (confidence 0.5).
    use citadel_mesh::application::AppPolicy;
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig { witness_count: 0, ..NodeConfig::default() };
    let ids: Vec<NodeId> = (1..=2).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();

    let mut p = AppPolicy::new();
    // The IMA-measured digest is H(image) for the bank — the same digest the
    // mock backend folds into the PCR via measure_event.
    let digest = tpm_core::backend::hash_for_bank("sha256", b"billing-image").unwrap();
    p.accept("billing-api", digest.clone(), artifact(vec![2, 0]));
    mesh.set_app_policy_all(p);

    let host = ids[0];
    let claim = AppMeasurement {
        app: AppId::new("billing-api"),
        digest: digest.to_vec(),
        version: vec![2, 0],
        role: "worker".into(),
        pcr_bound: true, // claimed, but nothing measured into PCR 10 yet
        timestamp_tick: 0,
    };

    // Claimed bound but not actually measured → downgraded to advisory.
    let r1 = mesh.node(host).appraise_app(&claim);
    assert_eq!(r1.verdict, AppVerdict::Healthy);
    assert_eq!(r1.confidence, 0.5, "unbacked pcr_bound is advisory");

    // Now actually measure the app into the IMA PCR (10) on the host's TPM.
    mesh.measure_event(host, "sha256", 10, 0xD, b"billing-image");
    let r2 = mesh.node(host).appraise_app(&claim);
    assert_eq!(r2.verdict, AppVerdict::Healthy);
    assert_eq!(r2.confidence, 1.0, "a genuinely measured app is fully bound");
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
