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
pub mod operator;
mod redb_store;
pub mod shard;
mod store;

#[cfg(feature = "postgres-store")]
mod pg_store;
#[cfg(feature = "postgres-store")]
pub use pg_store::PgStore;

pub use redb_store::RedbStore;

pub use model::{
    AgreementView, DurabilityRecord, EvidenceDurabilityView, FleetHealth, NodeRecord, NodeView,
    ReportView, TimelineEvent,
};
pub use operator::{OperatorAction, OperatorAuditEntry, WriteError};
pub use store::{ControlPlaneStore, MemStore};

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Compact a subject's verdicts (CP7 rollup): per verifier, keep the first, the
/// last, and every verdict whose result differs from the previous — collapsing
/// runs of identical ballots while preserving transitions and the current value.
fn compact_verdicts(verdicts: Vec<AttestationResult>) -> Vec<AttestationResult> {
    let mut by_verifier: std::collections::BTreeMap<NodeId, Vec<AttestationResult>> =
        std::collections::BTreeMap::new();
    for v in verdicts {
        by_verifier.entry(v.verifier).or_default().push(v);
    }
    let mut out = Vec::new();
    for (_, mut group) in by_verifier {
        group.sort_by_key(|v| v.timestamp_tick);
        let n = group.len();
        for i in 0..n {
            let keep = i == 0 || i == n - 1 || group[i].result != group[i - 1].result;
            if keep {
                out.push(group[i].clone());
            }
        }
    }
    out
}

fn from_hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        if let Some(h) = s.get(i * 2..i * 2 + 2) {
            *byte = u8::from_str_radix(h, 16).unwrap_or(0);
        }
    }
    out
}

use std::collections::{HashMap, HashSet};

use citadel_mesh::crypto::MeshPublicKey;
use citadel_mesh::id::Epoch;
use citadel_mesh::membership::MemberUpdate;
use citadel_mesh::quarantine::OperatorQuarantineApproval;
use citadel_mesh::reference::ReferenceManifest;
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
    /// Registered operator keys allowed to authorize writes (CP5).
    operators: HashSet<MeshPublicKey>,
    /// Operator-authorized manifests awaiting relay into the mesh — the API
    /// validates + enqueues (no node needed); the host loop drains and
    /// broadcasts through the observer node (CP5 live `POST` wiring).
    pending_manifests: Vec<ReferenceManifest>,
    /// Operator-authorized quarantine approvals awaiting relay (CP5).
    pending_quarantine_approvals: Vec<OperatorQuarantineApproval>,
    /// Latest mesh tick the CP has observed — stamped onto operator audit
    /// entries created by the (tick-less) HTTP path.
    last_tick: u64,
    /// Shard identity for CP7 sharding: `(me, shards, replication)`. `None` = a
    /// single CP that owns the whole subject space.
    shard: Option<(shard::ShardId, Vec<shard::ShardId>, usize)>,
}

impl<S: ControlPlaneStore> ControlPlane<S> {
    pub fn new(store: S) -> Self {
        ControlPlane {
            store,
            epoch: 0,
            witness_count: 0,
            operators: HashSet::new(),
            pending_manifests: Vec::new(),
            pending_quarantine_approvals: Vec::new(),
            last_tick: 0,
            shard: None,
        }
    }

    /// Make this a CP7 shard: it ingests verdict/event/durability history only
    /// for subjects it owns under HRW (`shard::owns`), partitioning the subject
    /// space across shards. Membership is still ingested for every node (keys +
    /// roster). `replication` > 1 keeps hot-standby replicas.
    pub fn set_shard(
        &mut self,
        me: shard::ShardId,
        shards: Vec<shard::ShardId>,
        replication: usize,
    ) {
        self.shard = Some((me, shards, replication));
    }

    /// Update the shard set (e.g. after a shard joins or is lost) — the survivor
    /// expands to cover the departed shard's subjects on the next ingest, and
    /// backfills them from the shared store (CP7 self-heal).
    pub fn set_shards(&mut self, shards: Vec<shard::ShardId>) {
        if let Some((_, s, _)) = &mut self.shard {
            *s = shards;
        }
    }

    /// Whether this shard owns `subject` (always true for an un-sharded CP).
    pub fn responsible_for(&self, subject: &NodeId) -> bool {
        match &self.shard {
            None => true,
            Some((me, shards, replication)) => shard::owns(*me, *subject, shards, *replication),
        }
    }

    /// The latest mesh tick the CP has observed (used to stamp HTTP-path audits).
    pub fn current_tick(&self) -> u64 {
        self.last_tick
    }

    /// Register an operator key allowed to authorize writes (CP5).
    pub fn authorize_operator(&mut self, operator: MeshPublicKey) {
        self.operators.insert(operator);
    }

    /// Relay an **operator-authorized**, authority-signed reference manifest into
    /// the mesh (CP5 `POST /v1/policies`). The CP holds no key that decides
    /// trust: it (1) checks the operator is registered, (2) verifies the
    /// operator's signature over this manifest's content id, (3) verifies the
    /// manifest's own authority signature, then broadcasts it via the observer
    /// node and records a tamper-evident audit link. Nodes still adopt it only
    /// if they trust the manifest's authority. Returns the manifest content id.
    /// Validate an operator-authorized policy publish and **enqueue** it for
    /// relay — the node-free half used by the HTTP `POST /v1/policies` handler.
    /// Checks (1) the action authorizes this manifest, (2) the operator is
    /// registered, (3) its signature verifies, (4) the manifest's own authority
    /// signature verifies; then audits + enqueues. The host loop drains via
    /// [`Self::drain_pending_manifests`]. Returns the manifest content id.
    pub fn submit_policy(
        &mut self,
        action: &OperatorAction,
        manifest: &ReferenceManifest,
        tick: u64,
    ) -> Result<[u8; 32], WriteError> {
        let target = manifest.content_id();
        if action.target != target {
            return Err(WriteError::TargetMismatch);
        }
        if !self.operators.contains(&action.operator) {
            return Err(WriteError::Unauthorized);
        }
        if !action.verify() {
            return Err(WriteError::BadSignature);
        }
        if !manifest.verify_signature() {
            return Err(WriteError::BadArtifact);
        }
        self.last_tick = self.last_tick.max(tick);
        self.append_operator_audit("publish-policy", &target, &action.operator, tick);
        self.pending_manifests.push(manifest.clone());
        Ok(target)
    }

    /// Drain the manifests awaiting relay — the host loop broadcasts each
    /// through its observer node (`node.broadcast_reference_manifest`).
    pub fn drain_pending_manifests(&mut self) -> Vec<ReferenceManifest> {
        std::mem::take(&mut self.pending_manifests)
    }

    /// Validate, audit, and relay a policy publish in one call via the supplied
    /// observer node (the in-process convenience over
    /// [`Self::submit_policy`] + [`Self::drain_pending_manifests`]).
    pub fn publish_policy(
        &mut self,
        action: &OperatorAction,
        manifest: &ReferenceManifest,
        observer: &mut citadel_mesh::node::Node,
        tick: u64,
    ) -> Result<[u8; 32], WriteError> {
        let target = self.submit_policy(action, manifest, tick)?;
        for m in self.drain_pending_manifests() {
            observer.broadcast_reference_manifest(m);
        }
        Ok(target)
    }

    /// Validate + audit + **enqueue** a trusted operator's quarantine approval —
    /// the operator sign-off severe scopes require (CP5; node-free half). Checks
    /// the operator is registered and the approval's signature verifies, audits
    /// it, and queues it; the host loop relays via [`Self::drain_pending_quarantine_approvals`].
    /// Returns the approved proposal id.
    pub fn submit_quarantine_approval(
        &mut self,
        approval: OperatorQuarantineApproval,
        tick: u64,
    ) -> Result<[u8; 32], WriteError> {
        if !self.operators.contains(&approval.operator) {
            return Err(WriteError::Unauthorized);
        }
        if !approval.verify() {
            return Err(WriteError::BadSignature);
        }
        let pid = approval.proposal_id;
        self.last_tick = self.last_tick.max(tick);
        self.append_operator_audit("quarantine-approval", &pid, &approval.operator, tick);
        self.pending_quarantine_approvals.push(approval);
        Ok(pid)
    }

    /// Drain the quarantine approvals awaiting relay — the host loop relays each
    /// through its observer node (`node.relay_quarantine_approval`).
    pub fn drain_pending_quarantine_approvals(&mut self) -> Vec<OperatorQuarantineApproval> {
        std::mem::take(&mut self.pending_quarantine_approvals)
    }

    /// Validate, audit, and relay a quarantine approval in one call via the
    /// observer node (in-process convenience).
    pub fn relay_quarantine_approval(
        &mut self,
        approval: OperatorQuarantineApproval,
        observer: &mut citadel_mesh::node::Node,
        tick: u64,
    ) -> Result<[u8; 32], WriteError> {
        let pid = self.submit_quarantine_approval(approval, tick)?;
        for a in self.drain_pending_quarantine_approvals() {
            observer.relay_quarantine_approval(a);
        }
        Ok(pid)
    }

    fn append_operator_audit(
        &mut self,
        kind: &str,
        target: &[u8; 32],
        operator: &MeshPublicKey,
        tick: u64,
    ) {
        let chain = self.store.operator_audit();
        let seq = chain.len() as u64;
        let prev_hash = chain
            .last()
            .map(|e| from_hex32(&e.hash))
            .unwrap_or([0u8; 32]);
        let op_fp = operator.fingerprint();
        let hash = operator::entry_hash(seq, kind, target, &op_fp, tick, &prev_hash);
        self.store.append_operator_audit(OperatorAuditEntry {
            seq,
            kind: kind.to_string(),
            target: hex32(target),
            operator: hex32(&op_fp),
            tick,
            prev_hash: hex32(&prev_hash),
            hash: hex32(&hash),
        });
    }

    /// The operator-action audit chain (CP5) — what the CP relayed, in order.
    pub fn operator_audit(&self) -> Vec<OperatorAuditEntry> {
        self.store.operator_audit()
    }

    /// Whether the operator-action audit chain verifies intact (each link
    /// commits to the previous; a tampered or dropped entry breaks it).
    pub fn operator_audit_ok(&self) -> bool {
        let mut prev = [0u8; 32];
        for (i, e) in self.store.operator_audit().iter().enumerate() {
            if e.seq != i as u64 || from_hex32(&e.prev_hash) != prev {
                return false;
            }
            let recomputed = operator::entry_hash(
                e.seq,
                &e.kind,
                &from_hex32(&e.target),
                &from_hex32(&e.operator),
                e.tick,
                &prev,
            );
            if from_hex32(&e.hash) != recomputed {
                return false;
            }
            prev = recomputed;
        }
        true
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
        self.last_tick = self.last_tick.max(tick);
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
        if !self.responsible_for(&node.id()) {
            return; // another shard owns this subject's evidence
        }
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

    /// Steady-state rollup (CP7): compact each subject's verdict history,
    /// keeping **full fidelity for transitions** — per verifier, the first and
    /// last verdict plus every one whose result differs from the previous — and
    /// collapsing runs of identical ballots. The latest verdict per verifier is
    /// always kept, so derived trust and agreement are unchanged; only redundant
    /// steady-state repeats are dropped. Returns the number of verdicts removed.
    pub fn rollup_verdicts(&mut self) -> usize {
        let mut removed = 0;
        for n in self.store.all_nodes() {
            let cur = self.store.verdicts_for(&n.id);
            let before = cur.len();
            let compacted = compact_verdicts(cur);
            if compacted.len() < before {
                removed += before - compacted.len();
                self.store.replace_verdicts(&n.id, compacted);
            }
        }
        removed
    }

    /// Retention (CP7): drop timeline events older than `keep_from_tick`. The
    /// operator audit chain is immutable and never pruned.
    pub fn retain_events(&mut self, keep_from_tick: u64) {
        self.store.prune_events(keep_from_tick);
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
        // CP7 sharding: a shard only ingests history for subjects it owns.
        if !self.responsible_for(&v.subject) {
            return false;
        }
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
