//! MSS5: minting a node's mesh-TLS identity is gated on a mesh release — a node
//! with no authorized identity release cannot mint one.

use citadel_agent::{build_node, mint_mesh_identity, peer_id, peer_public_key};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;

#[test]
fn mint_mesh_identity_refuses_without_authorization() {
    let mesh_id = MeshId::new("mss-identity");
    let roster: Vec<(NodeId, _)> = (1u8..=3)
        .map(|s| (peer_id(&mesh_id, 1, s), peer_public_key(s)))
        .collect();
    let (mut node, _) = build_node(
        &mesh_id,
        1,
        "worker",
        NodeConfig {
            mesh_epoch: 1,
            ..NodeConfig::default()
        },
        &roster,
    );

    // No release round for this request id → the mesh has not authorized the
    // node's identity → minting is refused outright (no cert produced).
    assert!(mint_mesh_identity(&mut node, "node-1", [0u8; 32], 0).is_none());
}
