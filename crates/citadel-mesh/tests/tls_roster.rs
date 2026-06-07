//! E2 cert distribution — each node advertises its TLS certificate and the
//! pinnable peer roster assembles itself through membership gossip, so an agent
//! can build its mutual-TLS pin set from the mesh (no out-of-band exchange).

use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

fn mesh_of(n: u8) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 3,
        attestation_interval: 3,
        ..NodeConfig::default()
    };
    let ids: Vec<NodeId> = (1..=n)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    mesh.wire_full_membership();
    (mesh, ids)
}

// A distinct, stand-in DER cert per node (the real one comes from tpm-tls).
fn cert_for(seed: u8) -> Vec<u8> {
    vec![seed; 48]
}

#[test]
fn tls_certs_propagate_into_every_node_roster() {
    let (mut mesh, ids) = mesh_of(5);
    // Each node advertises its TLS cert.
    for (i, &id) in ids.iter().enumerate() {
        mesh.node_mut(id).set_tls_cert(cert_for(i as u8 + 1));
    }
    mesh.run(20);

    for (i, &id) in ids.iter().enumerate() {
        let roster = mesh.node(id).tls_roster();
        // Every other node's cert is known...
        assert_eq!(
            roster.len(),
            ids.len() - 1,
            "node {i} should know all peer certs"
        );
        // ...and the roster excludes self.
        assert!(
            !roster.iter().any(|(p, _)| *p == id),
            "roster excludes self"
        );
        // ...with the correct bytes for a sampled peer.
        for (j, &peer) in ids.iter().enumerate() {
            if peer != id {
                let got = roster
                    .iter()
                    .find(|(p, _)| *p == peer)
                    .map(|(_, c)| c.clone());
                assert_eq!(
                    got,
                    Some(cert_for(j as u8 + 1)),
                    "node {i} has peer {j}'s cert"
                );
            }
        }
    }
}

#[test]
fn an_enrolling_node_advertises_its_cert_in_the_signed_claim() {
    // Bootstrap-correct distribution: the candidate's TLS cert arrives in its
    // signed admission claim (on the plain channel, before mTLS is up), so
    // existing members can pin it.
    let (mut mesh, ids) = mesh_of(4);
    mesh.run(10);
    let cert = cert_for(99);
    let (outcome, candidate) = mesh.enroll_with_tls_cert(50, "worker", cert.clone());
    assert!(outcome.admitted, "candidate is admitted");

    // Every prior member now has the candidate's cert in its pin roster.
    for &id in &ids {
        let roster = mesh.node(id).tls_roster();
        let got = roster
            .iter()
            .find(|(p, _)| *p == candidate)
            .map(|(_, c)| c.clone());
        assert_eq!(
            got,
            Some(cert.clone()),
            "{id} pins the freshly-admitted candidate's cert"
        );
    }
}

#[test]
fn a_node_that_never_advertises_is_absent_from_the_roster() {
    let (mut mesh, ids) = mesh_of(3);
    // Only the first two advertise certs; the third stays silent.
    mesh.node_mut(ids[0]).set_tls_cert(cert_for(1));
    mesh.node_mut(ids[1]).set_tls_cert(cert_for(2));
    mesh.run(20);

    let roster = mesh.node(ids[0]).tls_roster();
    // node 0 learns node 1's cert but not node 2's (it never advertised).
    assert!(roster.iter().any(|(p, _)| *p == ids[1]));
    assert!(
        !roster.iter().any(|(p, _)| *p == ids[2]),
        "an un-advertised peer is not pinnable"
    );
}
