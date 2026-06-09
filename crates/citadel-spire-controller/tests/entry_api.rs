//! Live integration against a real SPIRE server's Entry API (#[ignore]d; needs a
//! reachable server — see deploy/run-controller-it.sh, which bridges the server's
//! admin socket to TCP via socat). Verifies the trust-driven registration
//! lifecycle: a Verified workload's entry is created, reconcile is idempotent, and
//! quarantine deletes it.

use citadel_mesh::NodeId;
use citadel_spiffe::{NodeTrustView, TrustDomain, TrustLevel};
use citadel_spire_controller::proto::spire::api::server::entry::v1::entry_client::EntryClient;
use citadel_spire_controller::{list_managed, reconcile, Workload};

fn view(level: TrustLevel) -> NodeTrustView {
    NodeTrustView {
        trust_level: level,
        quorum_agree: 3,
        quorum_total: 3,
        ima_policy: Some("baseline-v3".to_string()),
        tpm_ak: None,
        mma_profile: None,
        tpm_spec: None,
    }
}

#[tokio::test]
#[ignore]
async fn reconciles_registration_entries_against_live_spire() {
    let addr = std::env::var("CITADEL_SPIRE_ENTRY_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let mut client = EntryClient::connect(addr)
        .await
        .expect("connect to SPIRE Entry API");
    let td = TrustDomain::default();
    let node = NodeId([7u8; 32]);

    let verified = vec![Workload {
        node,
        service: "hexis".into(),
        view: view(TrustLevel::Verified),
    }];

    // Verified node → entry created in SPIRE.
    let p = reconcile(&mut client, &td, &verified).await.unwrap();
    assert_eq!(p.create.len(), 1, "creates the workload entry");
    let existing = list_managed(&mut client, &td).await.unwrap();
    assert!(
        existing
            .iter()
            .any(|e| e.spiffe_id == "spiffe://citadel.local/workload/hexis"),
        "SPIRE now holds the entry"
    );

    // Idempotent: a second reconcile changes nothing.
    let again = reconcile(&mut client, &td, &verified).await.unwrap();
    assert!(
        again.create.is_empty() && again.delete.is_empty(),
        "idempotent"
    );

    // Node quarantined → entry reconciled away.
    let quarantined = vec![Workload {
        node,
        service: "hexis".into(),
        view: view(TrustLevel::Quarantined),
    }];
    let removed = reconcile(&mut client, &td, &quarantined).await.unwrap();
    assert_eq!(removed.delete.len(), 1, "deletes the entry on quarantine");
    let after = list_managed(&mut client, &td).await.unwrap();
    assert!(
        !after.iter().any(|e| e.spiffe_id.contains("hexis")),
        "entry is gone"
    );
}
