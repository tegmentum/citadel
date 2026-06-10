//! P3 — the fact protocol live over the mesh: a node gossips an Assertion, each
//! witness runs its checker and gossips a vote, and a collector aggregates a
//! quorum into a witnessed-true FactAttestation. A false assertion gets none.

use citadel_facts::{
    votes_from_gossip, witness_gossiped_assertions, Assertion, FactAttestation, FactMessage,
    SbomHashChecker, FACT_TOPIC,
};
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

#[test]
fn an_sbom_fact_is_witnessed_true_over_gossip() {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let seeds: Vec<u8> = (1..=5).collect();
    let nodes: Vec<NodeId> = seeds
        .iter()
        .map(|s| mesh.add_node(*s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    mesh.run(8);

    let eligible: Vec<(NodeId, _)> = seeds
        .iter()
        .zip(&nodes)
        .map(|(s, id)| (*id, MeshKeypair::from_seed([*s; 32]).public()))
        .collect();
    let quorum = 3;
    let round = 100;

    // Node 0 gossips an SBOM assertion about itself.
    let evidence = b"<sbom for svc-a>".to_vec();
    let assertion = Assertion {
        subject: nodes[0],
        predicate: "sbom".to_string(),
        claim: blake3::hash(&evidence).to_hex().to_string(),
        beacon_round: round,
        evidence,
    };
    mesh.node_mut(nodes[0]).broadcast_app(
        FACT_TOPIC,
        FactMessage::Assert(assertion.clone()).to_bytes(),
    );
    mesh.run(6);

    // Each witness drains the assertion, runs its checker, and gossips its vote.
    for (s, id) in seeds.iter().zip(&nodes) {
        let drained = mesh.node_mut(*id).drain_app(FACT_TOPIC);
        let kp = MeshKeypair::from_seed([*s; 32]);
        for vote in witness_gossiped_assertions(&drained, &kp, *id, &SbomHashChecker, round) {
            mesh.node_mut(*id)
                .broadcast_app(FACT_TOPIC, FactMessage::Vote(vote).to_bytes());
        }
    }
    mesh.run(6);

    // A collector aggregates the gossiped votes into an attestation.
    let votes = votes_from_gossip(&mesh.node_mut(nodes[1]).drain_app(FACT_TOPIC));
    let att = FactAttestation {
        assertion_id: assertion.id(),
        subject: assertion.subject,
        predicate: assertion.predicate.clone(),
        claim: assertion.claim.clone(),
        beacon_round: round,
        votes,
    };
    assert!(
        att.witnessed_true(quorum, &eligible),
        "a checkable SBOM fact reaches quorum over gossip"
    );

    // A false claim: witnesses can't check it → no approvals → not witnessed.
    let false_assertion = Assertion {
        claim: "0".repeat(64),
        ..assertion
    };
    mesh.node_mut(nodes[0]).broadcast_app(
        FACT_TOPIC,
        FactMessage::Assert(false_assertion.clone()).to_bytes(),
    );
    mesh.run(6);
    for (s, id) in seeds.iter().zip(&nodes) {
        let drained = mesh.node_mut(*id).drain_app(FACT_TOPIC);
        let kp = MeshKeypair::from_seed([*s; 32]);
        for vote in witness_gossiped_assertions(&drained, &kp, *id, &SbomHashChecker, round) {
            mesh.node_mut(*id)
                .broadcast_app(FACT_TOPIC, FactMessage::Vote(vote).to_bytes());
        }
    }
    mesh.run(6);
    let false_votes = votes_from_gossip(&mesh.node_mut(nodes[2]).drain_app(FACT_TOPIC));
    let false_att = FactAttestation {
        assertion_id: false_assertion.id(),
        subject: false_assertion.subject,
        predicate: false_assertion.predicate,
        claim: false_assertion.claim,
        beacon_round: round,
        votes: false_votes,
    };
    assert!(
        !false_att.witnessed_true(quorum, &eligible),
        "an uncheckable claim is not witnessed"
    );
}
