//! Authorized measured-state transitions end-to-end through the mesh trust
//! machinery (design `measured-state-transitions.md`, Phase 1): an upgrade to a
//! measured component (kernel, firmware, …) changes a node's PCRs, which looks
//! identical to tamper — but an *authorized* new measured state keeps the node
//! trusted, while an *unauthorized* one is distrusted by the witness quorum.

use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{
    AcceptedReferences, ArtifactIdentity, BootProfile, FleetArtifactPolicy, PcrClass,
    ReferenceEntry, ReferenceManifest, Validity,
};
use citadel_mesh::state::TrustState;
use citadel_mesh::{MeshKeypair, NodeId};

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        reference_advertise_interval: 2,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n).map(|s| mesh.add_node(s, "worker", cfg.clone())).collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

#[test]
fn an_unauthorized_measured_change_is_distrusted() {
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    // A measured component changes with no authorization → looks like tamper.
    mesh.measured_state_change(node, "sha256", 0, &[0xAA; 32]);
    mesh.run(12);

    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Suspicious),
                "{observer} distrusts the unauthorized change on {node}"
            );
        }
    }
}

#[test]
fn a_change_on_a_volatile_pcr_does_not_distrust() {
    // §10.1: reclassify a churny PCR as Volatile and a change to it no longer
    // mints an "unknown" state — contrast `an_unauthorized_measured_change_is_
    // distrusted`, which is identical but leaves PCR 0 strict.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    mesh.set_pcr_class_all(0, PcrClass::Volatile);
    mesh.measured_state_change(node, "sha256", 0, &[0xAA; 32]);
    mesh.run(12);

    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Trusted),
                "{observer} ignores the volatile-PCR change on {node}"
            );
        }
    }
}

#[test]
fn an_authorized_upgrade_staged_first_never_dips() {
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    // The node upgrades and its new state is authorized across the fleet
    // before the mesh re-converges (the RVP computes the digest from the
    // approved build; here we read it from the upgraded node). Because the
    // authorization is in place before any witness challenges the new state,
    // trust never dips.
    mesh.measured_state_change(node, "sha256", 0, &[0xCC; 32]);
    let new_digest = mesh.pcr_digest(node, "sha256", 0);
    mesh.authorize_reference_all(0, new_digest, Validity::always());
    mesh.run(12);

    // The node is on the new (authorized) state; it stays trusted throughout —
    // an authorized upgrade is not a trust event.
    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Trusted),
                "{observer} keeps the upgraded {node} trusted"
            );
        }
    }
}

#[test]
fn authorizing_after_the_fact_restores_trust() {
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    // The node upgrades before the authorization lands → distrusted.
    mesh.measured_state_change(node, "sha256", 0, &[0xDD; 32]);
    mesh.run(12);
    for &observer in &ids {
        if observer != node {
            assert_eq!(mesh.trust_of(observer, node), Some(TrustState::Suspicious));
        }
    }

    // The authority now authorizes the new measured state (a late reference
    // update); subsequent witness challenges pass and trust recovers.
    let new_digest = mesh.pcr_digest(node, "sha256", 0);
    mesh.authorize_reference_all(0, new_digest, Validity::always());
    mesh.run(12);
    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Trusted),
                "{observer} restores trust in {node} once its state is authorized"
            );
        }
    }
}

#[test]
fn a_signed_manifest_authorizes_an_upgrade_fleet_wide() {
    // §10.2: acceptance comes from a signed manifest gossiped across the fleet,
    // not from an operator poking each verifier.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    let authority = MeshKeypair::from_seed([200u8; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));

    // The node upgrades; the authority signs a manifest accepting the new state
    // and one node gossips it to the fleet.
    mesh.measured_state_change(node, "sha256", 0, &[0x11; 32]);
    let new_digest = mesh.pcr_digest(node, "sha256", 0);
    let manifest = ReferenceManifest::issue(
        &authority,
        "prod",
        vec![ReferenceEntry::new(0, new_digest, Validity::always())],
        vec![],
    );
    mesh.broadcast_reference_manifest(ids[0], manifest);
    mesh.run(12);

    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Trusted),
                "{observer} trusts {node} after the signed manifest"
            );
        }
    }
}

#[test]
fn a_manifest_from_an_untrusted_issuer_is_ignored() {
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    // The fleet trusts `authority`, but a `rogue` key signs the manifest.
    let authority = MeshKeypair::from_seed([200u8; 32]);
    let rogue = MeshKeypair::from_seed([201u8; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));

    mesh.measured_state_change(node, "sha256", 0, &[0x22; 32]);
    let new_digest = mesh.pcr_digest(node, "sha256", 0);
    let manifest = ReferenceManifest::issue(
        &rogue,
        "prod",
        vec![ReferenceEntry::new(0, new_digest, Validity::always())],
        vec![],
    );
    mesh.broadcast_reference_manifest(ids[0], manifest);
    mesh.run(12);

    // The rogue manifest is not adopted; the unauthorized state is distrusted.
    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Suspicious),
                "{observer} ignores the rogue manifest and distrusts {node}"
            );
        }
    }
}

#[test]
fn revoking_an_artifact_version_distrusts_running_nodes() {
    // §10.2 revocation: a node runs an authorized kernel; that version is later
    // denylisted (CVE) and the node — byte-for-byte unchanged — is distrusted.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let node = ids[4];

    let authority = MeshKeypair::from_seed([200u8; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));
    mesh.set_artifact_policy_all(
        FleetArtifactPolicy::new().allow_channel("kernel", "prod").min_version("kernel", vec![6, 8, 0]),
    );

    // The node moves to kernel 6.8.0; the authority signs a manifest carrying
    // that provenance, and it is accepted fleet-wide.
    mesh.measured_state_change(node, "sha256", 0, &[0x33; 32]);
    let digest = mesh.pcr_digest(node, "sha256", 0);
    let entry = ReferenceEntry::new(0, digest, Validity::always()).with_artifact(ArtifactIdentity {
        component: "kernel".into(),
        publisher: "canonical".into(),
        channel: "prod".into(),
        version: vec![6, 8, 0],
        build_id: None,
    });
    mesh.broadcast_reference_manifest(ids[0], ReferenceManifest::issue(&authority, "prod", vec![entry], vec![]));
    mesh.run(12);
    for &observer in &ids {
        if observer != node {
            assert_eq!(mesh.trust_of(observer, node), Some(TrustState::Trusted));
        }
    }

    // A CVE lands: revoke 6.8.0 fleet-wide. The node is unchanged, but now
    // matches a forbidden artifact → distrusted on the next challenges.
    mesh.set_artifact_policy_all(
        FleetArtifactPolicy::new()
            .allow_channel("kernel", "prod")
            .min_version("kernel", vec![6, 8, 0])
            .deny_version("kernel", vec![6, 8, 0]),
    );
    mesh.run(12);
    for &observer in &ids {
        if observer != node {
            assert_eq!(
                mesh.trust_of(observer, node),
                Some(TrustState::Suspicious),
                "{observer} distrusts {node} running the revoked kernel"
            );
        }
    }
}

#[test]
fn anti_entropy_propagates_a_missed_manifest() {
    // §10.2 anti-entropy: a manifest reaches only one node; the digest
    // advertisement lets the rest detect the gap and pull it, converging.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(6);

    let authority = MeshKeypair::from_seed([200u8; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));

    let manifest = ReferenceManifest::issue(
        &authority,
        "prod",
        vec![ReferenceEntry::new(5, b"some-state".to_vec(), Validity::always())],
        vec![],
    );
    let id = manifest.content_id();

    // Deliver it to a single node only (no broadcast).
    assert!(mesh.node_mut(ids[0]).apply_reference_manifest(&manifest));
    assert!(mesh.node(ids[0]).has_reference_manifest(id));
    assert!(!mesh.node(ids[3]).has_reference_manifest(id), "others start without it");

    // Anti-entropy spreads it to the whole fleet.
    mesh.run(10);
    for &n in &ids {
        assert!(
            mesh.node(n).has_reference_manifest(id),
            "{n} pulled the missed manifest via anti-entropy"
        );
    }
}

#[test]
fn adopting_a_manifest_records_an_intact_audit_entry() {
    let (mut mesh, ids) = mesh_of(3);
    let authority = MeshKeypair::from_seed([200u8; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));
    let node = ids[0];

    let m1 = ReferenceManifest::issue(
        &authority,
        "prod",
        vec![ReferenceEntry::new(5, b"a".to_vec(), Validity::always())],
        vec![],
    );
    assert!(mesh.node_mut(node).apply_reference_manifest(&m1));
    assert_eq!(mesh.node(node).reference_audit_len(), 1);
    assert!(mesh.node(node).reference_audit_ok());

    // Idempotent: re-applying the same manifest adds no audit entry.
    mesh.node_mut(node).apply_reference_manifest(&m1);
    assert_eq!(mesh.node(node).reference_audit_len(), 1);

    // A distinct manifest extends the chain.
    let m2 = ReferenceManifest::issue(
        &authority,
        "prod",
        vec![ReferenceEntry::new(6, b"b".to_vec(), Validity::always())],
        vec![],
    );
    assert!(mesh.node_mut(node).apply_reference_manifest(&m2));
    assert_eq!(mesh.node(node).reference_audit_len(), 2);
    assert!(mesh.node(node).reference_audit_ok());
}

#[test]
fn an_assigned_boot_profile_appraises_a_subject_differently() {
    // §10.3: a subject assigned a boot profile is appraised against that
    // profile's accepted set, not the default golden — so a state acceptable to
    // its profile is trusted, while an identical state on an unassigned node
    // (default profile) is distrusted.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);
    let edge_node = ids[2];
    let plain_node = ids[4];

    // Both nodes move to the same new measured state.
    mesh.measured_state_change(edge_node, "sha256", 0, &[0x55; 32]);
    mesh.measured_state_change(plain_node, "sha256", 0, &[0x55; 32]);
    let new_pcr0 = mesh.pcr_digest(edge_node, "sha256", 0);
    let pcr7 = mesh.pcr_digest(edge_node, "sha256", 7);

    // An "edge" profile accepts the new state (PCR0) plus the unchanged PCR7.
    let mut accepted = AcceptedReferences::new("sha256");
    accepted.accept_entry(0, new_pcr0, Validity::always());
    accepted.accept_entry(7, pcr7, Validity::always());
    mesh.define_profile_all(BootProfile::new("edge", accepted));
    mesh.assign_profile_all(edge_node, "edge");

    mesh.run(12);

    // The edge node is trusted under its profile; the unassigned node — same
    // state, default golden — is distrusted.
    for &observer in &ids {
        if observer != edge_node {
            assert_eq!(
                mesh.trust_of(observer, edge_node),
                Some(TrustState::Trusted),
                "{observer} trusts {edge_node} under its edge profile"
            );
        }
        if observer != plain_node {
            assert_eq!(
                mesh.trust_of(observer, plain_node),
                Some(TrustState::Suspicious),
                "{observer} distrusts the unassigned {plain_node} in the same state"
            );
        }
    }
}

#[test]
fn old_and_new_both_pass_during_a_rolling_upgrade() {
    // The overlap window: some nodes upgraded, some not — all stay trusted
    // because both the old and the new measured state are authorized.
    let (mut mesh, ids) = mesh_of(6);
    mesh.run(12);

    // Upgrade two of the six to a new kernel state.
    let upgraded = [ids[2], ids[4]];
    for &n in &upgraded {
        mesh.measured_state_change(n, "sha256", 0, &[0x42; 32]);
    }
    // Authorize the new state alongside the (still-authorized) old golden.
    let new_digest = mesh.pcr_digest(upgraded[0], "sha256", 0);
    mesh.authorize_reference_all(0, new_digest, Validity::always());
    mesh.run(12);

    // Every node — upgraded or not — is trusted by every observer.
    for &observer in &ids {
        for &subject in &ids {
            if observer != subject {
                assert_eq!(
                    mesh.trust_of(observer, subject),
                    Some(TrustState::Trusted),
                    "mixed fleet stays trusted: {observer} → {subject}"
                );
            }
        }
    }
}
