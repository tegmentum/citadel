//! B2 — a Reference Value Provider derives a signed reference manifest from an
//! approved build (by replaying its measured-boot event log), operators adopt
//! it, and a matching state is accepted while a tampered one is
//! `REFERENCE_UNKNOWN`.

use std::collections::BTreeMap;

use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::reference::{
    AcceptedReferences, ArtifactIdentity, FleetArtifactPolicy, PcrClass, ReferenceMatchPolicy,
    ReferenceOutcome, Validity,
};
use citadel_mesh::rvp;
use tpm_core::backend::{hash_for_bank, PcrValue};
use tpm_core::eventlog::{ev, BootEventLog, EventType, MeasurementEvent};

/// An approved build's measured-boot log: firmware into PCR 0, the booted kernel
/// cmdline into PCR 8.
fn approved_log() -> BootEventLog {
    let fw = hash_for_bank("sha256", b"edk2-ovmf-approved").unwrap();
    let kver = b"/vmlinuz-6.8.0-117-generic root=LABEL=rootfs ro";
    let kdig = hash_for_bank("sha256", kver).unwrap();
    BootEventLog::new(vec![
        MeasurementEvent {
            pcr: 0,
            event_type: EventType::Unknown(ev::EFI_BOOT_SERVICES_APPLICATION),
            digests: vec![("sha256".into(), fw)],
            data: b"firmware".to_vec(),
        },
        MeasurementEvent {
            pcr: 8,
            event_type: EventType::Unknown(ev::IPL),
            digests: vec![("sha256".into(), kdig)],
            data: kver.to_vec(),
        },
    ])
}

/// Quote one PCR by folding its events from zero (what the TPM would report).
fn quoted(log: &BootEventLog, index: u32) -> PcrValue {
    let replay = log.replay("sha256").unwrap();
    PcrValue {
        bank: "sha256".into(),
        index,
        digest: replay.get(&index).unwrap().clone(),
    }
}

#[test]
fn rvp_manifest_accepts_the_approved_build_and_rejects_a_tampered_one() {
    let publisher = MeshKeypair::from_seed([7u8; 32]);
    let log = approved_log();

    // RVP replays the approved build and signs a manifest pinning PCRs 0 and 8.
    let manifest = rvp::issue_from_eventlog(
        &publisher,
        "prod",
        &log,
        "sha256",
        &[0, 8],
        Validity::always(),
        None,
        Vec::new(),
    )
    .unwrap();
    assert!(
        manifest.verify_signature(),
        "RVP manifest is self-consistently signed"
    );

    // An operator adopts it.
    let mut refs = AcceptedReferences::new("sha256");
    refs.adopt_manifest(&manifest);

    // A node that booted the approved build matches.
    let good = [quoted(&log, 0), quoted(&log, 8)];
    assert_eq!(
        refs.appraise(
            &good,
            0,
            0,
            ReferenceMatchPolicy::Flexible,
            citadel_mesh::reference::RetiredAction::Fail
        ),
        ReferenceOutcome::Accepted,
        "the approved build is accepted from the RVP reference"
    );

    // A tampered firmware PCR matches no accepted reference.
    let tampered = [
        PcrValue {
            bank: "sha256".into(),
            index: 0,
            digest: vec![0xAB; 32],
        },
        quoted(&log, 8),
    ];
    assert_eq!(
        refs.appraise(
            &tampered,
            0,
            0,
            ReferenceMatchPolicy::Flexible,
            citadel_mesh::reference::RetiredAction::Fail
        ),
        ReferenceOutcome::Unknown,
        "a tampered build is REFERENCE_UNKNOWN"
    );
}

#[test]
fn rvp_can_attach_artifact_provenance_for_fleet_policy() {
    let publisher = MeshKeypair::from_seed([9u8; 32]);
    // The RVP knows it approved kernel 6.8.0-117 (PCR 8 is the booted cmdline).
    let kver = b"/vmlinuz-6.8.0-117-generic root=LABEL=rootfs ro";
    let kdig = hash_for_bank("sha256", kver).unwrap();
    // For a Semantic index an accepted entry's digest is the *event* measurement
    // digest (what appraise_eventlog matches), so the RVP pins kdig here.
    let mut pcrs = BTreeMap::new();
    pcrs.insert(8u32, kdig.clone());

    let artifact = ArtifactIdentity {
        component: "kernel".into(),
        version: vec![6, 8, 0, 117],
        ..Default::default()
    };
    let manifest = rvp::issue_from_pcrs(
        &publisher,
        "prod",
        &pcrs,
        Validity::always(),
        Some((8, artifact)),
        Vec::new(),
    );

    // Adopt with PCR 8 classed Semantic so the per-digest artifact policy runs.
    let mut refs = AcceptedReferences::new("sha256");
    refs.set_pcr_class(8, PcrClass::Semantic);
    refs.adopt_manifest(&manifest);

    // A denylist on that kernel version denies the (RVP-provenanced) entry.
    refs.set_artifact_policy(FleetArtifactPolicy::new().deny_version("kernel", vec![6, 8, 0, 117]));
    let log = BootEventLog::new(vec![MeasurementEvent {
        pcr: 8,
        event_type: EventType::Unknown(ev::EFI_BOOT_SERVICES_APPLICATION),
        digests: vec![("sha256".into(), kdig)],
        data: b"kernel".to_vec(),
    }]);
    let semantic: std::collections::BTreeSet<u32> = [8].into_iter().collect();
    assert_eq!(
        refs.appraise_eventlog(&log, "sha256", &semantic),
        ReferenceOutcome::Denied,
        "fleet policy denies the RVP-provenanced kernel by version"
    );
}
