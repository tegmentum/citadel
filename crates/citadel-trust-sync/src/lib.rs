//! # citadel-trust-sync (SP4)
//!
//! The continuous loop that keeps SPIRE's registration entries in step with the
//! mesh's live trust: each pass reads the current trust for the managed
//! workloads and reconciles SPIRE (via SP3), so a node that loses trust has its
//! workloads' entries removed — the SP2 lease/deny-at-renewal model enforced
//! continuously rather than only at attestation. Trust-level transitions are
//! surfaced as [`TrustChange`]s so revocations can be audited loudly.
//!
//! The trust source is a closure (`Fn(&NodeId) -> NodeTrustView`) — in production
//! `|n| control_plane.spiffe_node_view(n)`; in tests a mock — so the engine is
//! decoupled and unit-testable. The SPIRE write path reuses
//! [`citadel_spire_controller::reconcile`].

use std::collections::HashMap;

use citadel_mesh::NodeId;
use citadel_spiffe::{NodeTrustView, TrustDomain, TrustLevel};
use citadel_spire_controller::proto::spire::api::server::entry::v1::entry_client::EntryClient;
use citadel_spire_controller::{reconcile, Plan, Workload};
use tonic::transport::Channel;

/// A workload the synchronizer manages: a service running on a mesh node.
#[derive(Clone, Debug)]
pub struct ManagedWorkload {
    pub node: NodeId,
    pub service: String,
}

/// A trust-level transition observed for a managed workload's node. A transition
/// into `Quarantined`/`Revoked` is a revocation; into `Verified` is an admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustChange {
    pub node: NodeId,
    pub service: String,
    pub from: Option<TrustLevel>,
    pub to: TrustLevel,
}

impl TrustChange {
    /// True if this transition revokes identity (into Quarantined/Revoked).
    pub fn is_revocation(&self) -> bool {
        matches!(self.to, TrustLevel::Quarantined | TrustLevel::Revoked)
            && self.from != Some(self.to)
    }
}

/// The outcome of one sync pass.
#[derive(Clone, Debug)]
pub struct SyncReport {
    pub plan: Plan,
    pub changes: Vec<TrustChange>,
}

/// Tracks the managed workloads and the last-seen trust level per node, so each
/// pass can both reconcile SPIRE and report what changed.
pub struct TrustSync {
    workloads: Vec<ManagedWorkload>,
    last: HashMap<NodeId, TrustLevel>,
}

impl TrustSync {
    pub fn new(workloads: Vec<ManagedWorkload>) -> Self {
        TrustSync {
            workloads,
            last: HashMap::new(),
        }
    }

    /// Read current trust for every managed workload, recording level transitions
    /// since the previous pass, and produce the [`Workload`]s for reconciliation.
    pub fn build<F: Fn(&NodeId) -> NodeTrustView>(
        &mut self,
        source: F,
    ) -> (Vec<Workload>, Vec<TrustChange>) {
        let mut out = Vec::with_capacity(self.workloads.len());
        let mut changes = Vec::new();
        for w in &self.workloads {
            let view = source(&w.node);
            let level = view.trust_level;
            let prev = self.last.get(&w.node).copied();
            if prev != Some(level) {
                changes.push(TrustChange {
                    node: w.node,
                    service: w.service.clone(),
                    from: prev,
                    to: level,
                });
                self.last.insert(w.node, level);
            }
            out.push(Workload {
                node: w.node,
                service: w.service.clone(),
                view,
            });
        }
        (out, changes)
    }

    /// One sync pass: read trust, reconcile SPIRE's entries to match, and return
    /// the applied plan + the observed transitions.
    pub async fn sync_once<F: Fn(&NodeId) -> NodeTrustView>(
        &mut self,
        client: &mut EntryClient<Channel>,
        td: &TrustDomain,
        source: F,
    ) -> anyhow::Result<SyncReport> {
        let (workloads, changes) = self.build(source);
        for c in &changes {
            if c.is_revocation() {
                tracing::warn!(node = ?c.node, service = %c.service, from = ?c.from, "mesh revoked trust; removing SPIRE identity");
            }
        }
        let plan = reconcile(client, td, &workloads).await?;
        Ok(SyncReport { plan, changes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn detects_transitions_and_revocations() {
        let mut sync = TrustSync::new(vec![ManagedWorkload {
            node: node(1),
            service: "hexis".into(),
        }]);

        // First pass: a new Verified node → an admission transition (from None).
        let (wl, changes) = sync.build(|_| view(TrustLevel::Verified));
        assert_eq!(wl.len(), 1);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].from, None);
        assert_eq!(changes[0].to, TrustLevel::Verified);
        assert!(!changes[0].is_revocation());

        // Steady state: no change.
        let (_, changes) = sync.build(|_| view(TrustLevel::Verified));
        assert!(changes.is_empty());

        // Compromise: Verified → Quarantined is a revocation.
        let (_, changes) = sync.build(|_| view(TrustLevel::Quarantined));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].from, Some(TrustLevel::Verified));
        assert!(changes[0].is_revocation());
    }
}
