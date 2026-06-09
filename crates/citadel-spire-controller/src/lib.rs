//! # citadel-spire-controller (SP3)
//!
//! Mesh trust drives SPIRE registration entries: a workload's entry exists while
//! its node is **Verified**, and is removed on quarantine/revocation — applied
//! through the SPIRE server **Entry API**. This is the live counterpart to the
//! SP2 plugin: where the plugin gates *attestation*, the controller manages the
//! *registration entries* SPIRE issues SVIDs against.
//!
//! The reconciliation is a pure diff (unit-tested); the Entry API calls are the
//! integration (runnable against the official `spire-server` image — see
//! `tests/` and `deploy/`).

// Generated SPIRE server-API client (multi-package, wired by include_file).
#[allow(clippy::all, clippy::pedantic, rustdoc::all)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/spire_api.rs"));
}

use citadel_mesh::NodeId;
use citadel_spiffe::{IssuanceDecision, NodeTrustView, SpiffeId, TrustDomain};

use proto::spire::api::server::entry::v1::entry_client::EntryClient;
use proto::spire::api::server::entry::v1::{
    BatchCreateEntryRequest, BatchDeleteEntryRequest, ListEntriesRequest,
};
use proto::spire::api::types::{Entry, Selector, Spiffeid};
use tonic::transport::Channel;

/// A workload whose SVID identity is gated on its node's mesh trust.
pub struct Workload {
    pub node: NodeId,
    pub service: String,
    pub view: NodeTrustView,
}

/// A registration entry Citadel wants SPIRE to hold (workload SVID under a node).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedEntry {
    pub spiffe_id: String,
    pub parent_id: String,
    pub selectors: Vec<String>,
}

/// An entry already present in SPIRE (its server-assigned id + SPIFFE id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingEntry {
    pub id: String,
    pub spiffe_id: String,
}

/// The reconciliation actions: entries to create, and SPIRE entry ids to delete.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub create: Vec<ManagedEntry>,
    pub delete: Vec<String>,
}

/// The entries Citadel wants: one per workload whose node is currently Verified
/// (issuance allowed). A node that is Suspect/Quarantined/Revoked yields none, so
/// its workloads' entries are reconciled away.
pub fn desired_entries(td: &TrustDomain, workloads: &[Workload]) -> Vec<ManagedEntry> {
    workloads
        .iter()
        .filter(|w| IssuanceDecision::for_level(w.view.trust_level).may_issue_new())
        .map(|w| ManagedEntry {
            spiffe_id: SpiffeId::workload(td, &w.service).to_string(),
            parent_id: SpiffeId::node(td, &w.node).to_string(),
            selectors: w.view.selectors(),
        })
        .collect()
}

/// Diff desired vs. existing (keyed by SPIFFE id): create the missing, delete the
/// managed entries no longer desired. Pure — the heart of the controller.
pub fn plan(existing: &[ExistingEntry], desired: &[ManagedEntry]) -> Plan {
    let existing_ids: std::collections::HashSet<&str> =
        existing.iter().map(|e| e.spiffe_id.as_str()).collect();
    let desired_ids: std::collections::HashSet<&str> =
        desired.iter().map(|e| e.spiffe_id.as_str()).collect();
    Plan {
        create: desired
            .iter()
            .filter(|d| !existing_ids.contains(d.spiffe_id.as_str()))
            .cloned()
            .collect(),
        delete: existing
            .iter()
            .filter(|e| !desired_ids.contains(e.spiffe_id.as_str()))
            .map(|e| e.id.clone())
            .collect(),
    }
}

fn spiffeid_to_proto(id: &SpiffeId) -> Spiffeid {
    Spiffeid {
        trust_domain: id.trust_domain.0.clone(),
        path: id.path.clone(),
    }
}

fn parse_selector(s: &str) -> Selector {
    match s.split_once(':') {
        Some((ty, value)) => Selector {
            r#type: ty.to_string(),
            value: value.to_string(),
        },
        None => Selector {
            r#type: String::new(),
            value: s.to_string(),
        },
    }
}

impl ManagedEntry {
    fn to_proto(&self) -> Entry {
        Entry {
            spiffe_id: SpiffeId::parse(&self.spiffe_id)
                .as_ref()
                .map(spiffeid_to_proto),
            parent_id: SpiffeId::parse(&self.parent_id)
                .as_ref()
                .map(spiffeid_to_proto),
            selectors: self.selectors.iter().map(|s| parse_selector(s)).collect(),
            ..Default::default()
        }
    }
}

/// List the **Citadel-managed** entries currently in SPIRE: workload entries
/// under our trust domain (path `/workload/...`). Pages through the Entry API.
pub async fn list_managed(
    client: &mut EntryClient<Channel>,
    td: &TrustDomain,
) -> anyhow::Result<Vec<ExistingEntry>> {
    let mut out = Vec::new();
    let mut page_token = String::new();
    loop {
        let resp = client
            .list_entries(ListEntriesRequest {
                filter: None,
                output_mask: None,
                page_size: 0,
                page_token: page_token.clone(),
            })
            .await?
            .into_inner();
        for e in resp.entries {
            if let Some(sid) = &e.spiffe_id {
                if sid.trust_domain == td.0 && sid.path.starts_with("/workload/") {
                    out.push(ExistingEntry {
                        id: e.id.clone(),
                        spiffe_id: format!("spiffe://{}{}", sid.trust_domain, sid.path),
                    });
                }
            }
        }
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }
    Ok(out)
}

/// Reconcile SPIRE's entries to match current mesh trust: create entries for
/// newly-Verified workloads, delete those whose node lost trust. Returns the
/// applied plan.
pub async fn reconcile(
    client: &mut EntryClient<Channel>,
    td: &TrustDomain,
    workloads: &[Workload],
) -> anyhow::Result<Plan> {
    let desired = desired_entries(td, workloads);
    let existing = list_managed(client, td).await?;
    let p = plan(&existing, &desired);

    if !p.create.is_empty() {
        client
            .batch_create_entry(BatchCreateEntryRequest {
                entries: p.create.iter().map(|m| m.to_proto()).collect(),
                output_mask: None,
            })
            .await?;
    }
    if !p.delete.is_empty() {
        client
            .batch_delete_entry(BatchDeleteEntryRequest {
                ids: p.delete.clone(),
            })
            .await?;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_spiffe::TrustLevel;

    fn node(seed: u8) -> NodeId {
        NodeId([seed; 32])
    }
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

    #[test]
    fn only_verified_nodes_yield_desired_entries() {
        let td = TrustDomain::default();
        let workloads = vec![
            Workload {
                node: node(1),
                service: "hexis".into(),
                view: view(TrustLevel::Verified),
            },
            Workload {
                node: node(2),
                service: "ragworks".into(),
                view: view(TrustLevel::Quarantined),
            },
        ];
        let desired = desired_entries(&td, &workloads);
        assert_eq!(desired.len(), 1);
        assert_eq!(
            desired[0].spiffe_id,
            "spiffe://citadel.local/workload/hexis"
        );
        assert_eq!(
            desired[0].parent_id,
            format!("spiffe://citadel.local/node/{}", "01".repeat(32))
        );
        assert!(desired[0]
            .selectors
            .contains(&"citadel:trust-level=verified".to_string()));
    }

    #[test]
    fn plan_creates_missing_and_deletes_untrusted() {
        let td = TrustDomain::default();
        let hexis = SpiffeId::workload(&td, "hexis").to_string();

        // Node verified, no entry yet → create.
        let desired = desired_entries(
            &td,
            &[Workload {
                node: node(1),
                service: "hexis".into(),
                view: view(TrustLevel::Verified),
            }],
        );
        let p = plan(&[], &desired);
        assert_eq!(p.create.len(), 1);
        assert!(p.delete.is_empty());

        // Entry exists, node still verified → no-op.
        let existing = vec![ExistingEntry {
            id: "entry-1".into(),
            spiffe_id: hexis.clone(),
        }];
        let p = plan(&existing, &desired);
        assert!(p.create.is_empty() && p.delete.is_empty());

        // Node quarantined → desired empty → delete the existing entry.
        let none = desired_entries(
            &td,
            &[Workload {
                node: node(1),
                service: "hexis".into(),
                view: view(TrustLevel::Quarantined),
            }],
        );
        let p = plan(&existing, &none);
        assert_eq!(p.delete, vec!["entry-1".to_string()]);
        assert!(p.create.is_empty());
    }

    #[test]
    fn selectors_split_into_type_and_value() {
        let s = parse_selector("citadel:trust-level=verified");
        assert_eq!(s.r#type, "citadel");
        assert_eq!(s.value, "trust-level=verified");
    }
}
