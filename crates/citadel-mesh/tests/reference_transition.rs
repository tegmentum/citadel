//! Authorized measured-state transitions end-to-end through the mesh trust
//! machinery (design `measured-state-transitions.md`, Phase 1): an upgrade to a
//! measured component (kernel, firmware, …) changes a node's PCRs, which looks
//! identical to tamper — but an *authorized* new measured state keeps the node
//! trusted, while an *unauthorized* one is distrusted by the witness quorum.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::Validity;
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
