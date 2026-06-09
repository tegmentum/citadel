//! Live SP4 against a real SPIRE server (#[ignore]d; reuses the controller's
//! socat bridge — see citadel-spire-controller/deploy/run-controller-it.sh, then
//! `cargo test -p citadel-trust-sync --test sync_live -- --ignored`). Drives the
//! continuous lifecycle: a Verified workload's SVID entry is created, then the
//! node is quarantined and the entry is revoked.

use citadel_mesh::NodeId;
use citadel_spiffe::{NodeTrustView, TrustDomain, TrustLevel};
use citadel_spire_controller::proto::spire::api::server::entry::v1::entry_client::EntryClient;
use citadel_trust_sync::{ManagedWorkload, TrustSync};

fn view(level: TrustLevel) -> NodeTrustView {
    NodeTrustView {
        trust_level: level,
        quorum_agree: 3,
        quorum_total: 3,
        ima_policy: Some("baseline-v3".to_string()),
        tpm_ak: None,
        mma_profile: None,
    }
}

#[tokio::test]
#[ignore]
async fn continuous_sync_admits_then_revokes() {
    let addr = std::env::var("CITADEL_SPIRE_ENTRY_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let mut client = EntryClient::connect(addr)
        .await
        .expect("connect to SPIRE Entry API");
    let td = TrustDomain::default();
    let node = NodeId([8u8; 32]);
    let mut sync = TrustSync::new(vec![ManagedWorkload {
        node,
        service: "ragworks".into(),
    }]);

    // Verified → SPIRE entry created; an admission transition is reported.
    let r = sync
        .sync_once(&mut client, &td, |_| view(TrustLevel::Verified))
        .await
        .unwrap();
    assert_eq!(r.plan.create.len(), 1);
    assert_eq!(r.changes.len(), 1);
    assert!(!r.changes[0].is_revocation());

    // Quarantined → SPIRE entry removed; a revocation is reported.
    let r = sync
        .sync_once(&mut client, &td, |_| view(TrustLevel::Quarantined))
        .await
        .unwrap();
    assert_eq!(r.plan.delete.len(), 1, "the SVID entry is revoked");
    assert!(r.changes.iter().any(|c| c.is_revocation()));
}
