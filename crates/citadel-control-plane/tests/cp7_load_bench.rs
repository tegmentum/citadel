//! CP7 load rig — a runnable synthetic fleet-scale benchmark. `#[ignore]`d so it
//! never runs in CI; run it explicitly:
//!
//! ```text
//! cargo test -p citadel-control-plane --release --test cp7_load_bench \
//!     -- --ignored --nocapture
//! ```
//!
//! Tunables (env): `CITADEL_BENCH_NODES` (default 10000),
//! `CITADEL_BENCH_VERIFIERS` (4), `CITADEL_BENCH_ROUNDS` (3). See
//! `docs/deploy/load-rig.md` for methodology, targets, and how to read the
//! output.

use std::time::Instant;

use citadel_control_plane::{ControlPlane, ControlPlaneStore, MemStore};
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::membership::MemberUpdate;
use citadel_mesh::state::LivenessState;
use citadel_mesh::types::{AttestationResult, Verdict};
use citadel_mesh::NodeId;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn nid(i: usize) -> NodeId {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&(i as u64).to_le_bytes());
    b[8] = 0xC0;
    NodeId(b)
}

fn member(id: NodeId, key: citadel_mesh::crypto::MeshPublicKey) -> MemberUpdate {
    MemberUpdate {
        node_id: id,
        public_key: key,
        incarnation: 0,
        liveness: LivenessState::Alive,
        tls_cert: None,
        observer: false,
        tpm_spec: None,
    }
}

fn verdict(kp: &MeshKeypair, subject: NodeId, result: Verdict, tick: u64) -> AttestationResult {
    AttestationResult {
        subject,
        verifier: NodeId(kp.public().fingerprint()),
        result,
        reason_codes: vec![],
        policy_revision: 1,
        confidence: 1.0,
        timestamp_tick: tick,
        signature: citadel_mesh::crypto::Signature::zero(),
    }
    .signed(kp)
}

#[test]
#[ignore = "load rig — run explicitly with --ignored --release"]
fn fleet_scale_ingestion_benchmark() {
    let nodes = env_usize("CITADEL_BENCH_NODES", 10_000);
    let n_verifiers = env_usize("CITADEL_BENCH_VERIFIERS", 4);
    let rounds = env_usize("CITADEL_BENCH_ROUNDS", 3);
    println!("\n== CP7 load rig == {nodes} nodes x {n_verifiers} verifiers x {rounds} rounds");

    let mut cp = ControlPlane::new(MemStore::new());
    let verifiers: Vec<MeshKeypair> = (0..n_verifiers)
        .map(|i| MeshKeypair::from_seed([(i + 1) as u8; 32]))
        .collect();
    for kp in &verifiers {
        cp.ingest_member(&member(NodeId(kp.public().fingerprint()), kp.public()), 0);
    }
    let subjects: Vec<NodeId> = (0..nodes).map(nid).collect();
    for (i, s) in subjects.iter().enumerate() {
        cp.ingest_member(
            &member(*s, MeshKeypair::from_seed([(i % 251) as u8; 32]).public()),
            0,
        );
    }

    // Ingestion throughput over `rounds` steady-state passes (every verifier
    // re-attests every subject each round — the worst-case verified stream).
    let total = nodes * n_verifiers * rounds;
    let t0 = Instant::now();
    for r in 0..rounds {
        for s in &subjects {
            for kp in &verifiers {
                cp.ingest_verdict(&verdict(kp, *s, Verdict::Pass, (r + 1) as u64));
            }
        }
    }
    let ingest = t0.elapsed();
    println!(
        "ingest: {total} verified verdicts in {:.2}s = {:.0} verdicts/s",
        ingest.as_secs_f64(),
        total as f64 / ingest.as_secs_f64()
    );

    // Fleet rollup query latency (the dashboard's hot read).
    let t1 = Instant::now();
    let h = cp.fleet_health();
    println!(
        "fleet_health() over {} nodes in {:.1}ms -> {} trusted",
        h.total,
        t1.elapsed().as_secs_f64() * 1000.0,
        h.trusted
    );
    assert_eq!(h.trusted, nodes);

    // Steady-state rollup compaction ratio.
    let before: usize = subjects
        .iter()
        .map(|s| cp.store().verdicts_for(s).len())
        .sum();
    let t2 = Instant::now();
    let removed = cp.rollup_verdicts();
    let after = before - removed;
    println!(
        "rollup: {before} -> {after} verdicts ({:.0}% collapsed) in {:.2}s",
        100.0 * removed as f64 / before.max(1) as f64,
        t2.elapsed().as_secs_f64()
    );
    // Trust is unchanged by rollup.
    assert_eq!(cp.fleet_health().trusted, nodes);
}
