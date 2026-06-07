//! Signed, quote-bound checkpoints (design §9–10): a node commits each sealed
//! log window's LtHash root to its attested measured state in a record signed
//! by its mesh key, with a TPM quote whose nonce binds it to the root. Honest
//! nodes' checkpoints are recorded and verified; a node that forks a sealed
//! window emits a conflicting checkpoint that every peer detects as
//! *attributable* equivocation (it holds two of the node's own signatures).

use citadel_mesh::evidence::payload_hash;
use citadel_mesh::harness::Mesh;
use citadel_mesh::logship::checkpoint_nonce;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

fn cfg() -> NodeConfig {
    NodeConfig {
        witness_count: 0,
        log_window_size: 8,
        log_advertise_interval: 2,
        checkpoint_enabled: true,
        ..NodeConfig::default()
    }
}

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let ids: Vec<NodeId> = (1..=n).map(|s| mesh.add_node(s, "worker", cfg())).collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

#[test]
fn peers_record_a_signed_quote_bound_checkpoint() {
    let (mut mesh, ids) = mesh_of(4);
    let origin = ids[0];
    // Two full sealed windows (seq 0..15, window_size 8 → windows 0 and 1).
    for i in 0..16u64 {
        mesh.node_mut(origin)
            .append_event(payload_hash(format!("event-{i}").as_bytes()));
    }
    mesh.run(20);

    let origin_root = mesh.node(origin).own_log_root();
    let _ = origin_root;
    for &peer in &ids[1..] {
        let cp = mesh
            .node(peer)
            .checkpoint_for(origin, 1, 0)
            .expect("peer recorded a checkpoint for the origin's sealed window 0");
        // The checkpoint is internally consistent: its quote binds the root.
        assert!(cp.quote_binds_root());
        assert_eq!(cp.quote.nonce, checkpoint_nonce(1, 0, &cp.lthash_root));
        // No equivocation seen for an honest node.
        assert!(mesh.node(peer).equivocation_proofs().is_empty());
        assert_ne!(mesh.trust_of(peer, origin), Some(TrustState::Suspicious));
    }
}

#[test]
fn a_forked_window_yields_an_attributable_equivocation_proof() {
    let (mut mesh, ids) = mesh_of(4);
    let forker = ids[2];

    // Build and checkpoint sealed window 0 (seq 0..11 seals window 0).
    for i in 0..12u64 {
        mesh.node_mut(forker)
            .append_event(payload_hash(format!("orig-{i}").as_bytes()));
    }
    mesh.run(20);
    for &peer in &ids {
        if peer != forker {
            assert!(mesh.node(peer).checkpoint_for(forker, 1, 0).is_some());
            assert_ne!(mesh.trust_of(peer, forker), Some(TrustState::Suspicious));
        }
    }

    // The node rewrites a sealed event — forking its own history. Its next
    // checkpoint carries a different (still validly-signed, quote-bound) root.
    mesh.node_mut(forker).rewrite_event(3, payload_hash(b"forged"));
    mesh.run(20);

    for &peer in &ids {
        if peer != forker {
            // Distrusted...
            assert_eq!(
                mesh.trust_of(peer, forker),
                Some(TrustState::Suspicious),
                "{peer} should distrust the equivocating {forker}"
            );
            // ...and holds non-repudiable proof: two conflicting checkpoints,
            // both signed by the forker, both with quotes bound to their roots.
            let proofs = mesh.node(peer).equivocation_proofs();
            assert!(!proofs.is_empty(), "{peer} should hold an equivocation proof");
            let (a, b) = &proofs[0];
            assert_eq!(a.node_id, forker);
            assert_eq!(b.node_id, forker);
            assert_ne!(a.lthash_root, b.lthash_root);
            assert!(a.quote_binds_root() && b.quote_binds_root());
        }
    }
}
