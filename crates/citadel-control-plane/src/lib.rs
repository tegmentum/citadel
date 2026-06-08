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

pub use model::{
    AgreementView, DurabilityRecord, EvidenceDurabilityView, FleetHealth, NodeRecord, NodeView,
    ReportView, TimelineEvent,
};
pub use store::{ControlPlaneStore, MemStore};

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

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

    /// Poll a node's evidence durability (CP3) — its own view of how many
    /// holders returned a verified receipt per sealed record. Durability is
    /// owner-centric (receipts flow owner↔holder, not by broadcast), so this is
    /// a per-node pull, not the gossip observer feed.
    pub fn poll_durability(&mut self, node: &citadel_mesh::node::Node) {
        self.store
            .upsert_durability(node.id(), node.evidence_durability());
    }

    /// A node's evidence-durability view (§17.3): each record is
    /// `reconstructable` only when ≥ threshold holders acknowledged.
    pub fn evidence_view(&self, owner: &NodeId) -> Option<EvidenceDurabilityView> {
        let _ = self.store.get_node(owner)?;
        let records: Vec<DurabilityRecord> = self
            .store
            .durability(owner)
            .into_iter()
            .map(|d| DurabilityRecord {
                record_id: hex32(&d.record_id),
                threshold: d.threshold,
                total: d.total,
                holders_acked: d.holders_acked,
                reconstructable: d.holders_acked >= d.threshold,
            })
            .collect();
        let records_total = records.len();
        let records_durable = records.iter().filter(|r| r.reconstructable).count();
        let durability_pct = if records_total == 0 {
            100.0
        } else {
            records_durable as f32 * 100.0 / records_total as f32
        };
        Some(EvidenceDurabilityView {
            node: owner.to_hex(),
            records,
            records_total,
            records_durable,
            durability_pct,
        })
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
    /// the member's facts + key. Observer-ness rides the update (M0). The first
    /// time a node is seen, a timeline `enrolled` event is recorded (CP4).
    pub fn ingest_member(&mut self, u: &MemberUpdate, tick: u64) {
        let prev = self.store.get_node(&u.node_id);
        let first_seen = prev.is_none();
        self.store.upsert_node(NodeRecord {
            id: u.node_id,
            public_key: u.public_key,
            role: prev.map(|p| p.role).unwrap_or_default(),
            liveness: u.liveness,
            observer: u.observer,
            last_seen_tick: tick,
        });
        if first_seen && !u.observer {
            self.record_event(tick, u.node_id, "enrolled", String::new());
        }
    }

    /// Append a forensic-timeline event (CP4).
    fn record_event(&mut self, tick: u64, subject: NodeId, kind: &str, detail: String) {
        self.store.append_event(TimelineEvent {
            tick,
            subject: subject.to_hex(),
            kind: kind.to_string(),
            detail,
        });
    }

    /// One subject's forensic timeline (§17 "what changed") — every entry backed
    /// by a verified artifact.
    pub fn timeline(&self, subject: &NodeId) -> Vec<TimelineEvent> {
        self.store.timeline_for(&subject.to_hex())
    }

    /// The fleet change feed: timeline events after the `since` tick cursor.
    pub fn events_since(&self, since: u64) -> Vec<TimelineEvent> {
        self.store.events_since(since)
    }

    /// Verify a node's audit-chain integrity (CP4) and timeline a break. Polled
    /// (owner-centric, like durability). `reference_audit_ok` is the node's
    /// hash-chain integrity check; a fully-relinked rewrite is caught instead by
    /// the mesh's witnessed chain heads (a stronger CP follow-up).
    pub fn poll_audit(&mut self, node: &citadel_mesh::node::Node, tick: u64) {
        if !node.reference_audit_ok() {
            self.record_event(
                tick,
                node.id(),
                "audit-broken",
                "reference audit chain".into(),
            );
        }
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
        // CP4: a verdict that flips the subject's derived trust is a timeline
        // event ("what changed"), carrying the triggering verdict's reasons.
        let before = self.derived_trust(&v.subject).0;
        self.store.append_verdict(v.clone());
        let after = self.derived_trust(&v.subject).0;
        if before != after {
            let reasons: Vec<String> = v.reason_codes.iter().map(|r| format!("{r:?}")).collect();
            let detail = if reasons.is_empty() {
                format!("{} → {}", model::trust_str(before), model::trust_str(after))
            } else {
                format!(
                    "{} → {} ({})",
                    model::trust_str(before),
                    model::trust_str(after),
                    reasons.join(", ")
                )
            };
            self.record_event(v.timestamp_tick, v.subject, "trust-transition", detail);
        }
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

    /// Fleet rollup (§17.1) over non-observer nodes' derived trust + evidence
    /// durability.
    pub fn fleet_health(&self) -> FleetHealth {
        let mut h = FleetHealth::default();
        let (mut records_total, mut records_durable) = (0usize, 0usize);
        for n in self.store.all_nodes() {
            if n.observer {
                continue;
            }
            let (trust, _, _) = self.derived_trust(&n.id);
            model::bump(&mut h, trust);
            for d in self.store.durability(&n.id) {
                records_total += 1;
                if d.holders_acked >= d.threshold {
                    records_durable += 1;
                }
            }
        }
        h.mesh_health_pct = if h.total == 0 {
            100.0
        } else {
            h.trusted as f32 * 100.0 / h.total as f32
        };
        h.evidence_durability_pct = if records_total == 0 {
            100.0
        } else {
            records_durable as f32 * 100.0 / records_total as f32
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
    fn trust_transition_is_recorded_on_the_timeline() {
        let mut cp = ControlPlane::new(MemStore::new());
        let subject_kp = MeshKeypair::from_seed([1; 32]);
        let subject = NodeId(subject_kp.public().fingerprint());
        let w: Vec<MeshKeypair> = (2u8..=5).map(|s| MeshKeypair::from_seed([s; 32])).collect();
        cp.ingest_member(&member(&subject_kp, false), 1);
        for kp in &w {
            cp.ingest_member(&member(kp, false), 1);
        }
        // First a Pass quorum (unknown → trusted), then a Fail quorum (→ suspicious).
        for kp in &w {
            cp.ingest_verdict(&verdict(kp, subject, Verdict::Pass, 10));
        }
        for kp in &w {
            cp.ingest_verdict(&verdict(kp, subject, Verdict::Fail, 20));
        }
        let tl = cp.timeline(&subject);
        assert!(tl.iter().any(|e| e.kind == "enrolled"));
        assert!(tl
            .iter()
            .any(|e| e.kind == "trust-transition" && e.detail.contains("trusted")));
        assert!(tl
            .iter()
            .any(|e| e.kind == "trust-transition" && e.detail.contains("suspicious")));
        // The change feed (tick cursor) returns the later transition only.
        assert!(cp.events_since(15).iter().all(|e| e.tick > 15));
        assert!(cp
            .events_since(15)
            .iter()
            .any(|e| e.detail.contains("suspicious")));
    }

    #[test]
    fn durability_needs_threshold_holders_to_be_reconstructable() {
        use citadel_mesh::evidence::EvidenceDurability;
        let mut cp = ControlPlane::new(MemStore::new());
        let owner_kp = MeshKeypair::from_seed([1; 32]);
        let owner = NodeId(owner_kp.public().fingerprint());
        cp.ingest_member(&member(&owner_kp, false), 1);

        // 2 of 3 required → NOT reconstructable; 3 of 3 → reconstructable.
        cp.store.upsert_durability(
            owner,
            vec![
                EvidenceDurability {
                    record_id: [1; 32],
                    threshold: 3,
                    total: 5,
                    holders_acked: 2,
                },
                EvidenceDurability {
                    record_id: [2; 32],
                    threshold: 3,
                    total: 5,
                    holders_acked: 3,
                },
            ],
        );
        let v = cp.evidence_view(&owner).unwrap();
        assert_eq!(v.records_total, 2);
        assert_eq!(
            v.records_durable, 1,
            "only the record with ≥ threshold acks is durable"
        );
        assert!(
            !v.records
                .iter()
                .find(|r| r.holders_acked == 2)
                .unwrap()
                .reconstructable
        );
        assert!(
            v.records
                .iter()
                .find(|r| r.holders_acked == 3)
                .unwrap()
                .reconstructable
        );
        assert!((v.durability_pct - 50.0).abs() < 0.01);
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
