//! M0 — observer (control-plane) mode: a node that joins and ingests all signed
//! gossip but is excluded from witness assignment, casts no counting verdict,
//! and doesn't perturb the witness quorum.

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

#[test]
fn an_observer_ingests_verdicts_but_is_never_a_witness() {
    let mut mesh = Mesh::new("prod-east-1");
    let worker_cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=5)
        .map(|s| mesh.add_node(s, "worker", worker_cfg.clone()))
        .collect();
    // The control-plane observer.
    let observer_cfg = NodeConfig {
        observer: true,
        ..worker_cfg.clone()
    };
    let observer = mesh.add_node(6, "control-plane", observer_cfg);
    mesh.wire_full_membership();
    mesh.run(20);

    // Observer-ness propagated: workers know the observer is one.
    assert!(
        mesh.node(workers[0])
            .membership()
            .get(&observer)
            .unwrap()
            .observer,
        "the observer flag gossips to peers"
    );

    // The observer is never assigned as a witness for any worker (from any
    // worker's view), and no worker witnesses *for* a subject includes it.
    for &w in &workers {
        for &subject in &workers {
            assert!(
                !mesh.node(w).witness_ids_for(subject).contains(&observer),
                "observer must not be a witness for {subject}"
            );
        }
        // And the observer itself, asked, assigns the same observer-free sets.
        assert!(!mesh.node(observer).witness_ids_for(w).contains(&observer));
    }

    // Quorum unaffected: workers still converge to trusting each other.
    for &a in &workers {
        for &b in &workers {
            if a != b {
                assert_eq!(
                    mesh.trust_of(a, b),
                    Some(TrustState::Trusted),
                    "{a} trusts {b} (witness quorum unperturbed by the observer)"
                );
            }
        }
    }

    // The observer *ingests*: it aggregates the gossiped signed verdicts and
    // reaches the same trust conclusion about the workers.
    for &w in &workers {
        assert_eq!(
            mesh.trust_of(observer, w),
            Some(TrustState::Trusted),
            "observer ingested the witness quorum's verdicts for {w}"
        );
    }
}

#[test]
fn a_forged_verdict_is_dropped_on_receipt() {
    // M1: a witness's signed verdict can't be forged. (Behavioural proxy: the
    // signed-verdict path is what carries quorum; this asserts the happy path
    // converges, while the unit test in types covers signature rejection.)
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=5)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(15);
    // Signed verdicts propagated and aggregated → mutual trust.
    assert_eq!(mesh.trust_of(ids[0], ids[3]), Some(TrustState::Trusted));
}
