//! CP7 scale-out: HRW observer sharding partitions the subject space, survives a
//! shard loss, and sustains a synthetic fleet-scale verdict stream.

use std::collections::HashMap;

use citadel_control_plane::shard::responsible_shards;
use citadel_control_plane::{ControlPlane, ControlPlaneStore, MemStore};
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::harness::Mesh;
use citadel_mesh::membership::MemberUpdate;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::LivenessState;
use citadel_mesh::types::{AttestationResult, ReasonCode, Verdict};
use citadel_mesh::NodeId;

fn nid(i: usize) -> NodeId {
    let mut b = [0u8; 32];
    b[0] = (i & 0xff) as u8;
    b[1] = ((i >> 8) & 0xff) as u8;
    b[2] = 0xC0; // keep subject ids disjoint from the small shard ids
    NodeId(b)
}

#[test]
fn hrw_sharding_is_balanced_and_minimally_disruptive() {
    let shards: Vec<NodeId> = (0..5).map(|i| NodeId([i as u8; 32])).collect();
    let subjects: Vec<NodeId> = (0..1000).map(nid).collect();

    // Balanced: ~200 each across 5 shards; allow a generous band.
    let mut counts: HashMap<NodeId, usize> = HashMap::new();
    for s in &subjects {
        *counts
            .entry(responsible_shards(*s, &shards, 1)[0])
            .or_insert(0) += 1;
    }
    assert_eq!(counts.len(), 5, "every shard owns some subjects");
    for (_, c) in counts {
        assert!(
            (100..=320).contains(&c),
            "roughly balanced ownership, got {c}"
        );
    }

    // Minimal disruption: drop one shard — only its subjects reassign.
    let smaller: Vec<NodeId> = shards[..4].to_vec();
    let dropped = shards[4];
    let (mut moved, mut kept) = (0, 0);
    for s in &subjects {
        let before = responsible_shards(*s, &shards, 1)[0];
        let after = responsible_shards(*s, &smaller, 1)[0];
        if before == dropped {
            moved += 1;
        } else {
            assert_eq!(
                before, after,
                "a subject not owned by the dropped shard keeps its owner"
            );
            kept += 1;
        }
    }
    assert!(moved > 0 && kept > 0);
}

fn sharded_mesh() -> (Mesh, Vec<NodeId>, NodeId, NodeId) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=8)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let obs_a = mesh.add_node(
        20,
        "cp-a",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    let obs_b = mesh.add_node(
        21,
        "cp-b",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();
    mesh.run(28);
    (mesh, workers, obs_a, obs_b)
}

#[test]
fn two_shards_partition_the_subject_space() {
    let (mut mesh, workers, obs_a, obs_b) = sharded_mesh();
    let shards = vec![obs_a, obs_b];

    let mut cp_a = ControlPlane::new(MemStore::new());
    cp_a.set_shard(obs_a, shards.clone(), 1);
    let mut cp_b = ControlPlane::new(MemStore::new());
    cp_b.set_shard(obs_b, shards.clone(), 1);

    cp_a.observe(mesh.node_mut(obs_a), 28);
    cp_b.observe(mesh.node_mut(obs_b), 28);

    for &w in &workers {
        let a = !cp_a.store().verdicts_for(&w).is_empty();
        let b = !cp_b.store().verdicts_for(&w).is_empty();
        assert!(
            a ^ b,
            "subject {w} owned by exactly one shard (replication 1)"
        );
        // The owner matches the HRW decision.
        let owner = responsible_shards(w, &shards, 1)[0];
        assert_eq!(a, owner == obs_a);
    }
}

#[test]
fn a_surviving_shard_takes_over_on_shard_loss() {
    let (mut mesh, workers, obs_a, obs_b) = sharded_mesh();
    let shards = vec![obs_a, obs_b];

    let mut cp_a = ControlPlane::new(MemStore::new());
    cp_a.set_shard(obs_a, shards.clone(), 1);
    cp_a.observe(mesh.node_mut(obs_a), 28);

    // A subject obs_b owns (cp_a doesn't have it).
    let b_owned = *workers
        .iter()
        .find(|w| responsible_shards(**w, &shards, 1)[0] == obs_b)
        .expect("some subject hashes to obs_b");
    assert!(cp_a.store().verdicts_for(&b_owned).is_empty());

    // obs_b is lost: cp_a's shard set shrinks to just itself → it owns all.
    cp_a.set_shards(vec![obs_a]);
    mesh.run(16); // fresh verdicts keep flowing on the broadcast bus
    cp_a.observe(mesh.node_mut(obs_a), 44);

    assert!(
        !cp_a.store().verdicts_for(&b_owned).is_empty(),
        "the survivor took over the lost shard's subject"
    );
}

#[test]
fn ingestion_sustains_a_synthetic_fleet_stream() {
    // A volume smoke test (no real mesh): 600 subjects x 4 verifiers = 2400
    // signed verdicts ingested and aggregated correctly.
    let mut cp = ControlPlane::new(MemStore::new());
    let verifiers: Vec<MeshKeypair> = (0..4)
        .map(|i| MeshKeypair::from_seed([100 + i; 32]))
        .collect();
    for kp in &verifiers {
        cp.ingest_member(
            &MemberUpdate {
                node_id: NodeId(kp.public().fingerprint()),
                public_key: kp.public(),
                incarnation: 0,
                liveness: LivenessState::Alive,
                tls_cert: None,
                observer: false,
                tpm_spec: None,
            },
            1,
        );
    }
    let subjects: Vec<NodeId> = (0..600).map(nid).collect();
    for (i, s) in subjects.iter().enumerate() {
        cp.ingest_member(
            &MemberUpdate {
                node_id: *s,
                public_key: MeshKeypair::from_seed([(i % 200) as u8; 32]).public(),
                incarnation: 0,
                liveness: LivenessState::Alive,
                tls_cert: None,
                observer: false,
                tpm_spec: None,
            },
            1,
        );
        for kp in &verifiers {
            let v = AttestationResult {
                subject: *s,
                verifier: NodeId(kp.public().fingerprint()),
                result: Verdict::Pass,
                reason_codes: vec![ReasonCode::PcrMismatch; 0],
                policy_revision: 1,
                confidence: 1.0,
                timestamp_tick: 10,
                signature: citadel_mesh::crypto::Signature::zero(),
            }
            .signed(kp);
            assert!(cp.ingest_verdict(&v));
        }
    }
    let h = cp.fleet_health();
    assert_eq!(h.total, 600 + 4, "subjects + verifier members");
    assert_eq!(h.trusted, 600, "all 600 subjects unanimous Pass → trusted");
    assert_eq!(
        h.unknown, 4,
        "the 4 verifiers have no verdicts about themselves"
    );
}

fn mk_member(kp: &MeshKeypair) -> MemberUpdate {
    MemberUpdate {
        node_id: NodeId(kp.public().fingerprint()),
        public_key: kp.public(),
        incarnation: 0,
        liveness: LivenessState::Alive,
        tls_cert: None,
        observer: false,
        tpm_spec: None,
    }
}

fn mk_verdict(kp: &MeshKeypair, subject: NodeId, result: Verdict, tick: u64) -> AttestationResult {
    AttestationResult {
        subject,
        verifier: NodeId(kp.public().fingerprint()),
        result,
        reason_codes: if result == Verdict::Fail {
            vec![ReasonCode::PcrMismatch]
        } else {
            vec![]
        },
        policy_revision: 1,
        confidence: 1.0,
        timestamp_tick: tick,
        signature: citadel_mesh::crypto::Signature::zero(),
    }
    .signed(kp)
}

#[test]
fn rollup_collapses_steady_state_but_keeps_trust_and_transitions() {
    let mut cp = ControlPlane::new(MemStore::new());
    let v = MeshKeypair::from_seed([5; 32]);
    cp.ingest_member(&mk_member(&v), 1);
    let subj_kp = MeshKeypair::from_seed([9; 32]);
    let subject = NodeId(subj_kp.public().fingerprint());
    cp.ingest_member(&mk_member(&subj_kp), 1);

    // A long steady-state run of identical Pass verdicts.
    for t in 1..=8 {
        assert!(cp.ingest_verdict(&mk_verdict(&v, subject, Verdict::Pass, t)));
    }
    assert_eq!(cp.store().verdicts_for(&subject).len(), 8);
    let trust_before = cp.derived_trust(&subject);

    let removed = cp.rollup_verdicts();
    assert_eq!(removed, 6, "collapse the 6 redundant middle Pass verdicts");
    assert_eq!(
        cp.store().verdicts_for(&subject).len(),
        2,
        "keep first + last"
    );
    assert_eq!(
        cp.derived_trust(&subject),
        trust_before,
        "derived trust is unchanged"
    );

    // A transition is preserved with full fidelity.
    let s2_kp = MeshKeypair::from_seed([10; 32]);
    let s2 = NodeId(s2_kp.public().fingerprint());
    cp.ingest_member(&mk_member(&s2_kp), 1);
    cp.ingest_verdict(&mk_verdict(&v, s2, Verdict::Pass, 1));
    cp.ingest_verdict(&mk_verdict(&v, s2, Verdict::Pass, 2));
    cp.ingest_verdict(&mk_verdict(&v, s2, Verdict::Fail, 3));
    let removed = cp.rollup_verdicts();
    assert_eq!(removed, 1, "drop only the redundant middle Pass");
    let kept = cp.store().verdicts_for(&s2);
    assert_eq!(kept.len(), 2);
    assert!(
        kept.iter().any(|x| x.result == Verdict::Fail),
        "the transition to Fail survives"
    );
}

#[test]
fn retention_prunes_old_events_but_not_the_audit() {
    use citadel_control_plane::TimelineEvent;
    let mut s = MemStore::new();
    for t in [10u64, 20, 30, 40, 50] {
        s.append_event(TimelineEvent {
            tick: t,
            subject: "x".into(),
            kind: "trust-transition".into(),
            detail: String::new(),
        });
    }
    let mut cp = ControlPlane::new(s);
    cp.retain_events(30);
    assert_eq!(cp.events_since(0).len(), 3, "ticks 10 and 20 pruned");
    assert_eq!(cp.events_since(35).len(), 2);
}
