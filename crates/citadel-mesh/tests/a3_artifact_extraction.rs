//! A3 — structured `ArtifactIdentity` extraction from real events, validated
//! against the real OVMF/GRUB corpus captured for A1. Proves a node can judge a
//! kernel by version **directly from the event log**, with no signed manifest
//! naming it.

use std::collections::BTreeSet;

use citadel_mesh::reference::{
    extract_kernel_artifact, extract_kernel_cmdline, AcceptedReferences, FleetArtifactPolicy,
    ReferenceOutcome,
};
use tpm_core::eventlog::BootEventLog;

const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tpm-core/tests/fixtures/eventlog/ubuntu-24.04-ovmf-amd64.bin"
);

fn corpus() -> BootEventLog {
    let raw = std::fs::read(CORPUS).expect("A1 corpus fixture present");
    BootEventLog::parse_tcg(&raw).expect("real OVMF log parses")
}

fn semantic_pcrs() -> BTreeSet<u32> {
    // GRUB measures the kernel command line into PCRs 8 and 9.
    [8u32, 9].into_iter().collect()
}

#[test]
fn extracts_the_booted_kernel_version_from_the_real_log() {
    let log = corpus();
    let kernel = extract_kernel_artifact(&log, "sha256")
        .expect("a kernel artifact is derivable from the real log");
    assert_eq!(kernel.component, "kernel");
    // The fixture booted vmlinuz-6.8.0-117-generic.
    assert_eq!(kernel.version, vec![6, 8, 0, 117]);

    let cmdline = extract_kernel_cmdline(&log, "sha256").expect("a booted cmdline");
    assert!(cmdline.contains("/vmlinuz-6.8.0-117-generic"));
    assert!(cmdline.contains("root=LABEL=cloudimg-rootfs"));
    // The recovered cmdline is the *booted* one, not the recovery menuentry.
    assert!(!cmdline.contains("recovery"));
    assert!(!cmdline.contains("menuentry"));
}

#[test]
fn version_baseline_gates_an_unmanifested_kernel() {
    let log = corpus();
    let refs = AcceptedReferences::new("sha256");

    // Baseline below the booted kernel → accepted (6.8.0-117 >= 6.8.0-100).
    let mut ok = refs.clone();
    ok.set_artifact_policy(FleetArtifactPolicy::new().min_version("kernel", vec![6, 8, 0, 100]));
    assert_eq!(
        ok.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Accepted,
        "a kernel at/above baseline is accepted"
    );

    // Baseline above the booted kernel → denied (6.8.0-117 < 6.8.0-200), with
    // no manifest naming the kernel anywhere.
    let mut stale = refs.clone();
    stale.set_artifact_policy(FleetArtifactPolicy::new().min_version("kernel", vec![6, 8, 0, 200]));
    assert_eq!(
        stale.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Denied,
        "a below-baseline kernel is denied straight from the event log"
    );
}

#[test]
fn denylisting_the_exact_booted_version_denies() {
    let log = corpus();
    let mut refs = AcceptedReferences::new("sha256");
    refs.set_artifact_policy(FleetArtifactPolicy::new().deny_version("kernel", vec![6, 8, 0, 117]));
    assert_eq!(
        refs.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Denied,
        "the exact booted kernel version on the denylist is rejected"
    );

    // A different version on the denylist does not affect this boot.
    let mut other = AcceptedReferences::new("sha256");
    other.set_artifact_policy(FleetArtifactPolicy::new().deny_version("kernel", vec![5, 15, 0, 1]));
    assert_eq!(
        other.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Accepted
    );
}

#[test]
fn cmdline_policy_applies_to_the_booted_line_not_the_menuentry_blocks() {
    let log = corpus();

    // require a token the booted cmdline has → accepted.
    let mut req_ok = AcceptedReferences::new("sha256");
    req_ok.set_artifact_policy(FleetArtifactPolicy::new().require_cmdline("root=LABEL=cloudimg-rootfs"));
    assert_eq!(
        req_ok.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Accepted
    );

    // require a token absent from the booted cmdline → denied.
    let mut req_no = AcceptedReferences::new("sha256");
    req_no.set_artifact_policy(FleetArtifactPolicy::new().require_cmdline("lockdown=confidentiality"));
    assert_eq!(
        req_no.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Denied
    );

    // CRUCIAL real-log property: "recovery"/"nomodeset" appear in the recovery
    // *menuentry* GRUB measures, but NOT in what booted. Denying them must not
    // trip on the menuentry blocks.
    let mut deny_recovery = AcceptedReferences::new("sha256");
    deny_recovery.set_artifact_policy(FleetArtifactPolicy::new().deny_cmdline("nomodeset"));
    assert_eq!(
        deny_recovery.appraise_eventlog(&log, "sha256", &semantic_pcrs()),
        ReferenceOutcome::Accepted,
        "a token only in the recovery menuentry must not falsely deny the booted kernel"
    );
}
