//! # citadel-control-plane
//!
//! A **verifying aggregator** over the attestation mesh — the data layer behind
//! the monitoring/visualization API (`monitoring-control-plane.md`,
//! `control-plane-roadmap.md` CP1). It is explicitly **not a root of trust**:
//!
//! * every verdict it counts is **re-verified** against the verifier's mesh key
//!   (M1's signed [`AttestationResult`]) before it reaches the store, so a
//!   compromised store or relay can't fabricate agreement;
//! * node **trust is derived** from those verified verdicts (the mesh decides
//!   trust; the CP recomputes it), never asserted;
//! * the store is **pluggable** ([`ControlPlaneStore`]) — the backend is a
//!   deployment choice, not baked into the logic.
//!
//! Ingestion is fed by an observer [`citadel_mesh::node::Node`] (M0) in the host
//! process; this crate is transport-agnostic — hand it the (already
//! envelope-authenticated) `MemberUpdate`s and `AttestationResult`s and it
//! verifies, stores, and aggregates.

pub mod api;
mod model;
mod store;

pub use model::{AgreementView, FleetHealth, NodeRecord, NodeView, ReportView};
pub use store::{ControlPlaneStore, MemStore};

use std::collections::HashMap;

use citadel_mesh::id::Epoch;
use citadel_mesh::membership::MemberUpdate;
use citadel_mesh::state::TrustState;
use citadel_mesh::types::{AttestationResult, Verdict};
use citadel_mesh::NodeId;

/// The control plane over a pluggable [`ControlPlaneStore`].
pub struct ControlPlane<S: ControlPlaneStore> {
    store: S,
    /// Mesh params needed to **recompute** witness assignment (CP2); captured
    /// from the observer node via [`Self::observe`]. `(0, 0)` until set —
    /// agreement then reports all reporters as unassigned.
    epoch: u64,
    witness_count: usize,
}

impl<S: ControlPlaneStore> ControlPlane<S> {
    pub fn new(store: S) -> Self {
        ControlPlane {
            store,
            epoch: 0,
            witness_count: 0,
        }
    }

    /// Set the mesh params (epoch, witnesses-per-subject) used to recompute
    /// witness assignment for agreement records. Usually set via `observe`.
    pub fn set_mesh_params(&mut self, epoch: u64, witness_count: usize) {
        self.epoch = epoch;
        self.witness_count = witness_count;
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Pull the current verified state from an observer [`Node`](citadel_mesh::node::Node)
    /// (M0) — the live ingestion feed (CP1): every known member's facts + every
    /// verified verdict it has buffered since the last call.
    pub fn observe(&mut self, node: &mut citadel_mesh::node::Node, tick: u64) {
        self.set_mesh_params(node.mesh_epoch(), node.witness_count());
        for m in node.membership().iter() {
            self.ingest_member(&m.update(), tick);
        }
        for v in node.drain_observed_verdicts() {
            self.ingest_verdict(&v);
        }
    }

    /// The roster the mesh assigns witnesses over: known non-observer members.
    fn witness_roster(&self) -> Vec<NodeId> {
        self.store
            .all_nodes()
            .into_iter()
            .filter(|n| !n.observer)
            .map(|n| n.id)
            .collect()
    }

    /// The latest **verified** verdict per verifier about `subject`, restricted
    /// to `revision` (the claim being appraised).
    fn latest_verdicts(
        &self,
        subject: &NodeId,
        revision: u64,
    ) -> HashMap<NodeId, AttestationResult> {
        let mut latest: HashMap<NodeId, AttestationResult> = HashMap::new();
        for v in self.store.verdicts_for(subject) {
            if v.policy_revision != revision {
                continue;
            }
            latest
                .entry(v.verifier)
                .and_modify(|cur| {
                    if v.timestamp_tick >= cur.timestamp_tick {
                        *cur = v.clone();
                    }
                })
                .or_insert(v);
        }
        latest
    }

    /// The agreement record for a subject (§17.4): the **recomputed** assigned
    /// witness set, who reports what at the latest revision, who is silent, and
    /// the dissenters' reasons. `None` if the subject isn't a known member.
    pub fn agreement(&self, subject: &NodeId) -> Option<AgreementView> {
        let _ = self.store.get_node(subject)?;
        // The revision being appraised = the latest seen among its verdicts.
        let revision = self
            .store
            .verdicts_for(subject)
            .iter()
            .map(|v| v.policy_revision)
            .max()
            .unwrap_or(0);
        let ws = citadel_mesh::witness::assign(
            *subject,
            &self.witness_roster(),
            Epoch(self.epoch),
            self.witness_count,
        );
        let latest = self.latest_verdicts(subject, revision);

        let mut agree = 0usize;
        let mut reported = 0usize;
        let mut silent = Vec::new();
        let mut dissenters = Vec::new();
        for w in &ws.witnesses {
            match latest.get(w) {
                None => silent.push(w.to_hex()),
                Some(v) => {
                    reported += 1;
                    if v.result == Verdict::Pass {
                        agree += 1;
                    } else {
                        dissenters.push(ReportView {
                            verifier: w.to_hex(),
                            verdict: model::verdict_str(v.result).to_string(),
                            reasons: v.reason_codes.iter().map(|r| format!("{r:?}")).collect(),
                        });
                    }
                }
            }
        }
        Some(AgreementView {
            subject: subject.to_hex(),
            policy_revision: revision,
            assigned: ws.witnesses.iter().map(|w| w.to_hex()).collect(),
            quorum_threshold: ws.quorum_threshold,
            agree,
            reported,
            silent,
            dissenters,
        })
    }

    /// Ingest a (verified-by-the-observer-envelope) membership update: record
    /// the member's facts + key. Observer-ness rides the update (M0).
    pub fn ingest_member(&mut self, u: &MemberUpdate, tick: u64) {
        let prev = self.store.get_node(&u.node_id);
        self.store.upsert_node(NodeRecord {
            id: u.node_id,
            public_key: u.public_key,
            role: prev.map(|p| p.role).unwrap_or_default(),
            liveness: u.liveness,
            observer: u.observer,
            last_seen_tick: tick,
        });
    }

    /// Ingest a verifier's verdict. **Re-verifies the signature** (M1) against
    /// the verifier's known mesh key; an unknown verifier or a bad signature is
    /// rejected (`false`) and never stored — so the CP's agreement can't be
    /// forged. Returns whether the verdict was accepted.
    pub fn ingest_verdict(&mut self, v: &AttestationResult) -> bool {
        let Some(verifier) = self.store.get_node(&v.verifier) else {
            return false; // verifier not (yet) known — can't authenticate it
        };
        if !v.verify_signature(&verifier.public_key) {
            return false;
        }
        self.store.append_verdict(v.clone());
        true
    }

    /// Derive a subject's trust from its **verified** verdicts: the latest
    /// verdict per verifier, by majority. `Unknown` if unobserved. (CP2 refines
    /// this into the full agreement record — recomputed assigned-witness set,
    /// silence detection, dissenters.)
    pub fn derived_trust(&self, subject: &NodeId) -> (TrustState, usize, usize) {
        let mut latest: HashMap<NodeId, &AttestationResult> = HashMap::new();
        let verdicts = self.store.verdicts_for(subject);
        for v in &verdicts {
            latest
                .entry(v.verifier)
                .and_modify(|cur| {
                    if v.timestamp_tick >= cur.timestamp_tick {
                        *cur = v;
                    }
                })
                .or_insert(v);
        }
        let total = latest.len();
        if total == 0 {
            return (TrustState::Unknown, 0, 0);
        }
        let pass = latest
            .values()
            .filter(|v| v.result == Verdict::Pass)
            .count();
        let fail = latest
            .values()
            .filter(|v| v.result == Verdict::Fail)
            .count();
        let warn = latest
            .values()
            .filter(|v| v.result == Verdict::Warn)
            .count();
        // Any Fail among the latest verdicts → Suspicious; otherwise a
        // Warn-leaning subject (no Pass majority) → Degraded; else Trusted.
        let trust = if fail > 0 {
            TrustState::Suspicious
        } else if warn > 0 && pass * 2 <= total {
            TrustState::Degraded
        } else {
            TrustState::Trusted
        };
        (trust, pass, total)
    }

    /// A node as presented to operators (facts + derived trust + witness tally).
    pub fn node_view(&self, id: &NodeId) -> Option<NodeView> {
        let n = self.store.get_node(id)?;
        let (trust, agree, total) = self.derived_trust(id);
        let last_rev = self
            .store
            .verdicts_for(id)
            .iter()
            .map(|v| v.policy_revision)
            .max()
            .unwrap_or(0);
        Some(NodeView {
            id: id.to_hex(),
            role: n.role,
            liveness: model::liveness_str(n.liveness).to_string(),
            trust: model::trust_str(trust).to_string(),
            witnesses_agree: agree,
            witnesses_total: total,
            last_policy_revision: last_rev,
            last_seen_tick: n.last_seen_tick,
        })
    }

    /// Every non-observer node, as operator views.
    pub fn nodes(&self) -> Vec<NodeView> {
        self.store
            .all_nodes()
            .into_iter()
            .filter(|n| !n.observer)
            .filter_map(|n| self.node_view(&n.id))
            .collect()
    }

    /// Fleet rollup (§17.1) over non-observer nodes' derived trust.
    pub fn fleet_health(&self) -> FleetHealth {
        let mut h = FleetHealth::default();
        for n in self.store.all_nodes() {
            if n.observer {
                continue;
            }
            let (trust, _, _) = self.derived_trust(&n.id);
            model::bump(&mut h, trust);
        }
        h.mesh_health_pct = if h.total == 0 {
            100.0
        } else {
            h.trusted as f32 * 100.0 / h.total as f32
        };
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_mesh::crypto::MeshKeypair;
    use citadel_mesh::state::LivenessState;
    use citadel_mesh::types::ReasonCode;

    fn member(kp: &MeshKeypair, observer: bool) -> MemberUpdate {
        MemberUpdate {
            node_id: NodeId(kp.public().fingerprint()),
            public_key: kp.public(),
            incarnation: 0,
            liveness: LivenessState::Alive,
            tls_cert: None,
            observer,
        }
    }

    fn verdict(
        verifier: &MeshKeypair,
        subject: NodeId,
        result: Verdict,
        tick: u64,
    ) -> AttestationResult {
        AttestationResult {
            subject,
            verifier: NodeId(verifier.public().fingerprint()),
            result,
            reason_codes: if result == Verdict::Fail {
                vec![ReasonCode::PcrMismatch]
            } else {
                vec![]
            },
            policy_revision: 5,
            confidence: 1.0,
            timestamp_tick: tick,
            signature: citadel_mesh::crypto::Signature::zero(),
        }
        .signed(verifier)
    }

    #[test]
    fn pluggable_store_roundtrips_and_derives_trust() {
        let mut cp = ControlPlane::new(MemStore::new());
        let subject_kp = MeshKeypair::from_seed([1; 32]);
        let subject = NodeId(subject_kp.public().fingerprint());
        let w: Vec<MeshKeypair> = (2u8..=5).map(|s| MeshKeypair::from_seed([s; 32])).collect();

        // Learn the subject + witnesses.
        cp.ingest_member(&member(&subject_kp, false), 1);
        for kp in &w {
            cp.ingest_member(&member(kp, false), 1);
        }

        // 3 Pass verdicts → Trusted.
        for kp in &w[..3] {
            assert!(cp.ingest_verdict(&verdict(kp, subject, Verdict::Pass, 10)));
        }
        let v = cp.node_view(&subject).unwrap();
        assert_eq!(v.trust, "trusted");
        assert_eq!((v.witnesses_agree, v.witnesses_total), (3, 3));
    }

    #[test]
    fn a_forged_verdict_is_rejected_and_not_counted() {
        let mut cp = ControlPlane::new(MemStore::new());
        let subject = NodeId([9; 32]);
        let real = MeshKeypair::from_seed([2; 32]);
        let impostor = MeshKeypair::from_seed([3; 32]);
        cp.ingest_member(&member(&real, false), 1);

        // A verdict claiming to be from `real` but signed by the impostor.
        let mut forged = verdict(&impostor, subject, Verdict::Fail, 10);
        forged.verifier = NodeId(real.public().fingerprint());
        assert!(!cp.ingest_verdict(&forged), "forged verdict rejected");
        assert!(cp.store().verdicts_for(&subject).is_empty());
    }

    #[test]
    fn fleet_health_excludes_observers_and_rolls_up() {
        let mut cp = ControlPlane::new(MemStore::new());
        let obs = MeshKeypair::from_seed([100; 32]);
        cp.ingest_member(&member(&obs, true), 1); // observer — excluded

        let good = MeshKeypair::from_seed([1; 32]);
        let bad = MeshKeypair::from_seed([2; 32]);
        let gid = NodeId(good.public().fingerprint());
        let bid = NodeId(bad.public().fingerprint());
        cp.ingest_member(&member(&good, false), 1);
        cp.ingest_member(&member(&bad, false), 1);
        let w = MeshKeypair::from_seed([50; 32]);
        cp.ingest_member(&member(&w, false), 1);
        cp.ingest_verdict(&verdict(&w, gid, Verdict::Pass, 10));
        cp.ingest_verdict(&verdict(&w, bid, Verdict::Fail, 10));

        let h = cp.fleet_health();
        assert_eq!(h.total, 3); // good, bad, witness — observer excluded
        assert_eq!(h.trusted, 1); // good (Pass verdict)
        assert_eq!(h.suspicious, 1); // bad (Fail verdict)
        assert_eq!(h.unknown, 1); // the witness has no verdicts about *itself*
    }
}
