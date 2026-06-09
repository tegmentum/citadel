//! A self-contained demo of the control-plane dashboard: builds an in-process
//! mesh (healthy workers + one tampered node + shipped evidence + an
//! operator-published policy), feeds it into a ControlPlane, keeps it live, and
//! serves the dashboard + API. Open the printed URL in a browser.
//!
//!   cargo run -p citadel-control-plane --example dashboard_demo
//!   # then open http://127.0.0.1:8088/

use std::sync::{Arc, Mutex};
use std::time::Duration;

use citadel_control_plane::{api, ControlPlane, MemStore, OperatorAction};
use citadel_mesh::attest::TrustAnchors;
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::evidence::payload_hash;
use citadel_mesh::harness::Mesh;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::reference::{ReferenceEntry, ReferenceManifest, Validity};
use citadel_mesh::NodeId;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut mesh = Mesh::new("prod-east-1");
    let cfg = NodeConfig {
        witness_count: 4,
        attestation_interval: 3,
        pcr_selection: vec![0, 7],
        log_window_size: 8,
        evidence_replication: true,
        evidence_data_shards: 3,
        evidence_parity_shards: 2,
        ..NodeConfig::default()
    };
    let workers: Vec<NodeId> = (1..=6)
        .map(|s| mesh.add_node(s, "worker", cfg.clone()))
        .collect();
    let observer = mesh.add_node(
        20,
        "control-plane",
        NodeConfig {
            observer: true,
            ..cfg.clone()
        },
    );
    mesh.wire_full_membership();

    // A fleet authority the nodes trust for reference manifests.
    let authority = MeshKeypair::from_seed([200; 32]);
    mesh.set_reference_authorities_all(TrustAnchors::with(authority.public()));

    // Let the mesh converge + ship a window of evidence from worker 0.
    for i in 0..12u64 {
        mesh.node_mut(workers[0])
            .append_event(payload_hash(format!("boot-{i}").as_bytes()));
    }
    mesh.run(24);

    // Tamper one node so it goes Suspicious (dissenting witnesses, a timeline
    // transition — the "what changed" the dashboard leads with).
    let bad = workers[5];
    mesh.measured_state_change(bad, "sha256", 0, &[0xAA; 32]);
    mesh.run(20);

    // The control plane, with a registered operator.
    let operator = MeshKeypair::from_seed([50; 32]);
    let mut cp = ControlPlane::new(MemStore::new());
    cp.authorize_operator(operator.public());
    cp.observe(mesh.node_mut(observer), 44);
    for &w in &workers {
        cp.poll_durability(mesh.node(w));
    }

    // An operator publishes a fleet policy (an audited write the dashboard shows).
    let manifest = ReferenceManifest::issue(
        &authority,
        "baseline-v3",
        vec![ReferenceEntry::new(0, vec![7u8; 32], Validity::always())],
        vec![],
    );
    let action = OperatorAction::sign(&operator, "publish-policy", manifest.content_id());
    let _ = cp.publish_policy(&action, &manifest, mesh.node_mut(observer), 44);

    let cp = Arc::new(Mutex::new(cp));

    // Keep it live: drive the mesh + re-observe so the change feed updates.
    let driver_cp = cp.clone();
    tokio::spawn(async move {
        let mut tick = 44u64;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            tick += 6;
            mesh.run(6);
            for &w in &workers {
                mesh.node_mut(w)
                    .append_event(payload_hash(format!("hb-{tick}-{w}").as_bytes()));
            }
            let mut g = driver_cp.lock().unwrap();
            g.observe(mesh.node_mut(observer), tick);
            for &w in &workers {
                g.poll_durability(mesh.node(w));
            }
        }
    });

    let addr = "127.0.0.1:8088".parse()?;
    println!("\n  Citadel dashboard demo — open  http://{addr}/\n");
    println!("  6 workers (one tampered → suspicious), shipped evidence, a published policy.");
    println!("  Ctrl-C to stop.\n");
    api::serve(addr, cp).await?;
    Ok(())
}
