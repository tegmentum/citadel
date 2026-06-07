//! E2 — mint_tls_identity is graceful: a backend that can't produce a real
//! ECDSA TLS cert (the demo MockBackend) yields None, so the agent falls back
//! to plain HTTP rather than panicking. (The real-backend path is covered by
//! mtls_transport.rs against the vTPM.)

use citadel_agent::{build_node, mint_tls_identity};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;

#[test]
fn mock_backend_yields_no_tls_identity_and_no_cert() {
    let mesh = MeshId::new("test");
    let (mut node, id) = build_node(&mesh, 1, "worker", NodeConfig::default(), &[]);
    let identity = mint_tls_identity(&mut node, &id.to_string());
    assert!(identity.is_none(), "MockBackend cannot mint a real TLS identity → plain HTTP");
}
