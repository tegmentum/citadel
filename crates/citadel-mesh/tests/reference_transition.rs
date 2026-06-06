//! Authorized measured-state transitions end-to-end through the mesh trust
//! machinery (design `measured-state-transitions.md`, Phase 1): an upgrade to a
//! measured component (kernel, firmware, …) changes a node's PCRs, which looks
//! identical to tamper — but an *authorized* new measured state keeps the node
//! trusted, while an *unauthorized* one is distrusted by the witness quorum.

use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{PcrClass, ReferenceEntry, ReferenceManifest, Validity};
use citadel_mesh::state::TrustState;
use citadel_mesh::{MeshKeypair, NodeId};

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
        vec![ReferenceEntry { index: 0, digest: new_digest, validity: Validity::always() }],
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
        vec![ReferenceEntry { index: 0, digest: new_digest, validity: Validity::always() }],
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
