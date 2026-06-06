//! The Citadel node agent: the SWIM failure-detector tick and the
//! envelope-handling loop (design §5.2, §9).
//!
//! A [`Node`] is driven by two entry points the transport calls:
//!
//! * [`Node::tick`] — advance one logical tick: run the suspicion timer,
//!   advance any in-flight probe, and (on the probe interval) start a new
//!   direct probe. Returns nothing; outbound messages accumulate in the
//!   outbox.
//! * [`Node::deliver`] — process one inbound [`GossipEnvelope`]: verify it,
//!   merge its piggybacked membership, and handle its message (PING/ACK,
//!   indirect probes, attestation).
//!
//! The caller drains [`Node::take_outbox`] and routes the messages. This
//! keeps the node pure and synchronous so the in-process [`crate::harness`]
//! can run a whole mesh deterministically.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::attest::{Attestor, ReferenceMeasurements, TrustAnchors};
use crate::reference::{AcceptedReferences, ReferenceMatchPolicy, RetiredAction, Validity};
use crate::crypto::MeshKeypair;
use crate::enrollment::{
    self, AdmissionReason, AdmissionVerdict, EnrollmentChallenge, EnrollmentClaim, EnrollmentVote,
};
use crate::erasure::{self, ErasureScheme, EvidenceFragment};
use crate::evidence::{self, assign_holders, EvidenceReceipt};
use crate::id::{Epoch, MeshId, NodeId};
use crate::logship::{
    decode_records, encode_records, DigestAdvertisement, EventLog, EventRecord, LogFragment,
    PlacementPolicy,
};
use crate::membership::Membership;
use crate::quarantine::{Ballot, QuarantineProposal, QuarantineScope, QuarantineVote};
use crate::state::{LivenessState, TrustState};
use crate::types::{
    AttestationChallenge, Endorsement, GossipEnvelope, GossipMessage, ReasonCode, Verdict,
};
use crate::witness;
use tpm_core::backend::TpmBackend;

/// Tunable SWIM / attestation parameters (design §9.8).
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Ticks between starting new direct probes.
    pub probe_interval: u64,
    /// Number of indirect peers asked to probe on escalation.
    pub indirect_k: usize,
    /// Ticks a member may stay `Suspect` before being confirmed `Faulty`.
    pub suspicion_timeout: u64,
    /// Max membership updates piggybacked per message.
    pub piggyback_limit: usize,
    /// PCR bank used for attestation.
    pub pcr_bank: String,
    /// PCR indices a challenge asks the subject to quote.
    pub pcr_selection: Vec<u32>,
    /// The policy revision this node is running.
    pub policy_revision: u64,
    /// Mesh epoch used for witness assignment (bump to rotate witnesses).
    pub mesh_epoch: u64,
    /// Number of witnesses assigned per subject (`0` disables witnessing —
    /// trust then comes only from a node's own direct challenges).
    pub witness_count: usize,
    /// Ticks between a witness re-challenging each of its subjects.
    pub attestation_interval: u64,
    /// Ticks a newly-admitted node stays probationary (passing attestation)
    /// before it may be promoted to `Trusted` (design §7.5).
    pub probation_period: u64,
    /// This node's boot epoch, stamped into its log events (log-shipping §6).
    pub boot_id: u64,
    /// LtHash log window size (events per window).
    pub log_window_size: u64,
    /// Ticks between advertising this node's log digests (`0` disables
    /// log-shipping).
    pub log_advertise_interval: u64,
    /// Ship sealed log windows as erasure-coded fragments to a bounded set of
    /// assigned holders (durable evidence vault; design §12.4) rather than
    /// relying on full-window replication to every peer. `false` keeps the
    /// legacy full-replica behaviour.
    pub evidence_replication: bool,
    /// Reed–Solomon data shards: any this many of `data + parity` fragments
    /// reconstruct a window.
    pub evidence_data_shards: usize,
    /// Reed–Solomon parity shards: holder losses tolerated before a window
    /// becomes unreconstructable.
    pub evidence_parity_shards: usize,
    /// Target placement policy for *newly* sealed windows: when `true`, the
    /// subject is excluded from its own holder set (separation of custody).
    /// Already-shipped windows keep their recorded policy until migration moves
    /// them (see [`evidence_migration_rate`](Self::evidence_migration_rate)).
    pub evidence_offbox: bool,
    /// How many windows may be migrating to the target policy at once (`0`
    /// disables migration). A small value bleeds old-policy windows over to the
    /// new policy slowly, never dropping a window below its reconstruction
    /// threshold (re-ship to the new holders, then drop the old ones).
    pub evidence_migration_rate: usize,
    /// How a verifier matches quoted PCRs against accepted reference sources:
    /// `Flexible` (standalone per-index + coupled profiles) or `CoupledOnly`
    /// (`measured-state-transitions.md`).
    pub reference_match: ReferenceMatchPolicy,
    /// How a verifier treats a quote that matches only a *retired* reference
    /// (an unpatched node): `Fail`, `Warn`, or `GraceThenFail`.
    pub retired_action: RetiredAction,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            probe_interval: 1,
            indirect_k: 2,
            suspicion_timeout: 3,
            piggyback_limit: 32,
            pcr_bank: "sha256".to_string(),
            pcr_selection: vec![0, 7],
            policy_revision: 1,
            mesh_epoch: 1,
            witness_count: 3,
            attestation_interval: 4,
            probation_period: 6,
            boot_id: 1,
            log_window_size: 16,
            log_advertise_interval: 5,
            evidence_replication: false,
            evidence_data_shards: 3,
            evidence_parity_shards: 2,
            evidence_offbox: false,
            evidence_migration_rate: 0,
            reference_match: ReferenceMatchPolicy::Flexible,
            retired_action: RetiredAction::Fail,
        }
    }
}

/// A snapshot of how a subject's assigned witnesses currently vote — the
/// data behind the dashboard's "agreement" view (design §17.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSummary {
    pub subject: NodeId,
    /// Number of witnesses assigned to the subject this epoch.
    pub assigned: usize,
    /// Of the assigned witnesses, how many have reported a verdict.
    pub reported: usize,
    pub pass: usize,
    pub fail: usize,
    /// Reports needed for a confident decision.
    pub quorum: usize,
}

/// An envelope addressed to a specific recipient.
pub struct Addressed {
    pub to: NodeId,
    pub envelope: GossipEnvelope,
}

/// Stage of an in-flight direct/indirect probe.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ProbeStage {
    Direct,
    Indirect,
}

struct PendingProbe {
    target: NodeId,
    stage: ProbeStage,
    /// Tick at which the current stage began.
    stage_tick: u64,
}

/// An indirect probe this node owes a requester: it pinged `target` and,
/// if `target` acks, must reply `PingReqAck{alive:true}` to `requester`.
struct OwedIndirect {
    requester: NodeId,
    target: NodeId,
    tick: u64,
}

/// A node agent.
pub struct Node {
    mesh_id: MeshId,
    id: NodeId,
    keypair: MeshKeypair,
    membership: Membership,
    attestor: Attestor,
    config: NodeConfig,
    tick: u64,
    sequence: u64,
    probe_cursor: usize,
    pending: Option<PendingProbe>,
    owed: Vec<OwedIndirect>,
    issued_challenges: Vec<AttestationChallenge>,
    /// The accepted measured states this node expects of peers it verifies
    /// (the Reference Value Provider's output; design §8.1, §14.2, and
    /// `measured-state-transitions.md`). Multi-valued with validity windows,
    /// so authorized upgrades roll without false distrust. Empty until
    /// installed from policy — verification is then Inconclusive.
    peer_reference: AcceptedReferences,
    /// Endorsers this node trusts to vouch for peers' AKs (design §8.1). Empty
    /// = endorsement not required (the early-phase self-certifying AK).
    anchors: TrustAnchors,
    /// This node's own AK endorsement, attached to the evidence it produces.
    endorsement: Option<Endorsement>,
    /// Latest attestation verdict per `subject → verifier` heard on the mesh
    /// (own + gossiped). Aggregated by assigned-witness quorum into trust.
    witness_reports: HashMap<NodeId, HashMap<NodeId, Verdict>>,
    /// Last tick this node (as a witness) challenged each subject.
    last_challenge: HashMap<NodeId, u64>,
    /// Tick at which each subject was admitted to probation — used to gate
    /// promotion to `Trusted` after the probation window.
    probation_start: HashMap<NodeId, u64>,
    /// Quarantine scope currently applied to each subject (design §13). While
    /// present, the subject's trust is frozen (sticky until a rejoin lifts it).
    quarantine: HashMap<NodeId, QuarantineScope>,
    /// This node's own measurement log (LtHash log-shipping).
    own_log: EventLog,
    /// Replicated copies of peers' logs, kept in sync by reconciliation — the
    /// distributed evidence vault.
    replicas: HashMap<NodeId, EventLog>,
    /// Roots observed for sealed `(node, boot, window)` log windows, used to
    /// detect a node forking its own history (equivocation).
    sealed_roots: HashMap<(NodeId, u64, u64), Vec<u8>>,
    /// Last tick this node advertised its log digests.
    last_log_advert: u64,
    /// Count of own-log records this node has served to replicas (the bytes
    /// the binary search actually transferred) — for observability/tests.
    log_records_served: usize,
    /// As an **origin**: sealed windows this node has erasure-shipped, keyed by
    /// `(boot, window)`, tracking which fragment indices holders have
    /// acknowledged (the live durability of each window).
    shipped_windows: HashMap<(u64, u64), ShippedWindow>,
    /// As a **holder**: shards this node stores for peers' sealed windows,
    /// keyed by `record_id` then fragment index.
    held_fragments: HashMap<[u8; 32], HashMap<usize, LogFragment>>,
    /// As a **recoverer**: shards gathered for an in-flight reconstruction.
    gathering: HashMap<[u8; 32], HashMap<usize, LogFragment>>,
    /// Records this node has successfully reconstructed from holders.
    recovered: HashSet<[u8; 32]>,
    outbox: Vec<Addressed>,
}

/// An origin's record of one sealed window it erasure-shipped to holders.
struct ShippedWindow {
    record_id: [u8; 32],
    scheme: ErasureScheme,
    /// The committed placement policy this window's holders were chosen under.
    policy: PlacementPolicy,
    /// The committed holders (shard `i` lives on `holders[i % holders.len()]`).
    holders: Vec<NodeId>,
    /// Fragment indices a committed holder has acknowledged storing.
    acked: HashSet<usize>,
    /// An in-flight migration to a new placement policy, if any.
    migrating: Option<Migration>,
}

/// An in-flight re-placement of a window onto a new holder set under a new
/// policy. The window stays reconstructable from its *committed* holders until
/// the new placement is durable, at which point we cut over and drop the old.
struct Migration {
    to: PlacementPolicy,
    /// The erasure scheme of the new placement (lets a parity bump ride the
    /// same migration as a policy change).
    scheme: ErasureScheme,
    holders: Vec<NodeId>,
    acked: HashSet<usize>,
}

/// A self-describing handle to a sealed window's durable placement — the
/// record id, its subject, the policy its holders were chosen under, and the
/// holder count (= the erasure scheme's `total`) at placement time. Carrying
/// both the policy *and* the count is what lets a recoverer replay the exact
/// holder set even after the mesh's current policy *or* erasure scheme has
/// changed (e.g. a parity bump paired with `OffBox`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowPlacement {
    pub record_id: [u8; 32],
    pub subject: NodeId,
    pub boot_id: u64,
    pub window_id: u64,
    pub policy: PlacementPolicy,
    pub holder_count: usize,
}

/// Sub-range width at which network reconciliation stops bisecting and pulls
/// the records (mirrors `logship::LEAF_WIDTH`).
const LOG_LEAF_WIDTH: u64 = 4;

impl Node {
    pub fn new(
        mesh_id: MeshId,
        id: NodeId,
        keypair: MeshKeypair,
        membership: Membership,
        attestor: Attestor,
        config: NodeConfig,
    ) -> Self {
        let config_window = config.log_window_size;
        Node {
            mesh_id,
            id,
            keypair,
            membership,
            attestor,
            config,
            tick: 0,
            sequence: 0,
            // Diversify the starting probe target by identity so a large
            // mesh covers (and detects failures in) all peers quickly,
            // rather than every node probing the same order in lockstep.
            probe_cursor: id.0[0] as usize,
            pending: None,
            owed: Vec::new(),
            issued_challenges: Vec::new(),
            peer_reference: AcceptedReferences::default(),
            anchors: TrustAnchors::default(),
            endorsement: None,
            witness_reports: HashMap::new(),
            last_challenge: HashMap::new(),
            probation_start: HashMap::new(),
            quarantine: HashMap::new(),
            own_log: EventLog::new(config_window),
            replicas: HashMap::new(),
            sealed_roots: HashMap::new(),
            last_log_advert: 0,
            log_records_served: 0,
            shipped_windows: HashMap::new(),
            held_fragments: HashMap::new(),
            gathering: HashMap::new(),
            recovered: HashSet::new(),
            outbox: Vec::new(),
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn membership(&self) -> &Membership {
        &self.membership
    }

    /// The node's attestor (its TPM backend + AK). Exposed so a test or
    /// operator harness can inspect or perturb the measured state.
    pub fn attestor(&self) -> &Attestor {
        &self.attestor
    }

    /// Install the golden reference this node uses to judge peers' quotes
    /// (from signed policy / a known-good node). Seeds a single-valued accepted
    /// set; further states are added by [`Self::accept_reference`] /
    /// [`Self::accept_reference_profile`] (later, a signed reference update).
    pub fn set_peer_reference(&mut self, reference: ReferenceMeasurements) {
        self.peer_reference = AcceptedReferences::from_reference(reference);
    }

    /// Add a standalone accepted measured state for one PCR index (e.g. the
    /// new kernel digest during an authorized transition).
    pub fn accept_reference(&mut self, index: u32, digest: Vec<u8>, validity: Validity) {
        self.peer_reference.accept_entry(index, digest, validity);
    }

    /// Add a coupled accepted profile (a set of `(index, digest)` accepted only
    /// together).
    pub fn accept_reference_profile(&mut self, pcrs: BTreeMap<u32, Vec<u8>>, validity: Validity) {
        self.peer_reference.accept_profile(pcrs, validity);
    }

    /// Install the endorsers this node trusts to vouch for peers' AKs. With a
    /// non-empty set, peers must present a valid endorsement or be flagged
    /// `AK_UNTRUSTED`.
    pub fn set_trust_anchors(&mut self, anchors: TrustAnchors) {
        self.anchors = anchors;
    }

    /// Attach this node's own AK endorsement, included in the evidence it
    /// produces so endorsement-requiring verifiers accept it.
    pub fn set_endorsement(&mut self, endorsement: Endorsement) {
        self.endorsement = Some(endorsement);
    }

    /// The public identifier of this node's AK, for an endorser to endorse.
    pub fn ak_public(&self) -> Vec<u8> {
        self.attestor.ak_public()
    }

    /// Capture this node's own current measured state over the configured
    /// PCR selection — e.g. to publish it as a golden from a trusted node.
    pub fn current_reference(&self) -> anyhow::Result<ReferenceMeasurements> {
        self.attestor
            .reference_over(&self.config.pcr_bank, &self.config.pcr_selection)
    }

    /// Seed knowledge of a peer (from a seed list / enrollment).
    pub fn learn_peer(
        &mut self,
        id: NodeId,
        key: crate::crypto::MeshPublicKey,
        role: &str,
        tick: u64,
    ) {
        self.membership.learn(id, key, role, tick);
    }

    // -- log-shipping (LtHash) ------------------------------------------

    /// Append a measurement event to this node's own log at the next sequence.
    pub fn append_event(&mut self, payload_hash: [u8; 32]) {
        let sequence = if self.own_log.is_empty() {
            0
        } else {
            self.own_log.max_sequence() + 1
        };
        self.own_log.append(EventRecord {
            node_id: self.id,
            boot_id: self.config.boot_id,
            sequence,
            payload_hash,
        });
    }

    /// The LtHash root of this node's own log.
    pub fn own_log_root(&self) -> Vec<u8> {
        self.own_log.root()
    }

    /// Overwrite an existing event's payload — models a node *forking its own
    /// history* (the rewrite changes the sealed window's root, which peers
    /// detect as equivocation). Not something an honest node does.
    pub fn rewrite_event(&mut self, sequence: u64, payload_hash: [u8; 32]) {
        if let Some(existing) = self.own_log.get(sequence).cloned() {
            self.own_log.append(EventRecord {
                payload_hash,
                ..existing
            });
        }
    }

    /// The LtHash root of this node's replica of `peer`'s log, if any.
    pub fn replica_root(&self, peer: NodeId) -> Option<Vec<u8>> {
        self.replicas.get(&peer).map(|l| l.root())
    }

    /// The LtHash root of every peer log this node currently replicates.
    pub fn replica_roots(&self) -> Vec<(NodeId, Vec<u8>)> {
        self.replicas.iter().map(|(id, log)| (*id, log.root())).collect()
    }

    /// Periodically advertise this node's per-window log digests to peers.
    fn advertise_logs(&mut self, now: u64) {
        if self.config.log_advertise_interval == 0 || self.own_log.is_empty() {
            return;
        }
        if now.saturating_sub(self.last_log_advert) < self.config.log_advertise_interval {
            return;
        }
        self.last_log_advert = now;
        let ads = self.own_log.advertise(self.id, self.config.boot_id);
        for ad in ads {
            self.broadcast(GossipMessage::LogDigest(ad));
        }
    }

    /// Handle a peer's log digest: detect equivocation, and reconcile our
    /// replica of that peer's log toward the advertised root.
    fn on_log_digest(&mut self, sender: NodeId, ad: DigestAdvertisement, _now: u64) {
        // Equivocation: once a window is sealed (the advertiser has moved
        // past it), its root is final. A different root for a sealed window
        // means the node forked its own history.
        let window_end = (ad.window_id + 1) * self.config.log_window_size;
        let sealed = ad.max_sequence + 1 >= window_end;
        if sealed {
            let key = (ad.node_id, ad.boot_id, ad.window_id);
            match self.sealed_roots.get(&key) {
                Some(prev) if *prev != ad.root => {
                    // CHECKPOINT_EQUIVOCATION — distrust the forking node.
                    self.membership.set_trust(&ad.node_id, TrustState::Suspicious);
                }
                None => {
                    self.sealed_roots.insert(key, ad.root.clone());
                }
                _ => {}
            }
        }

        // Reconcile our replica of the advertiser's log for this window: if
        // the window root disagrees, start a binary search over the window
        // rather than pulling the whole window.
        let replica = self
            .replicas
            .entry(ad.node_id)
            .or_insert_with(|| EventLog::new(self.config.log_window_size));
        if replica.window_root(ad.window_id) != ad.root {
            let lo = ad.window_id * self.config.log_window_size;
            let hi = lo + self.config.log_window_size;
            self.emit(sender, GossipMessage::LogRangeQuery { boot_id: ad.boot_id, lo, hi });
        }
    }

    /// Continue the binary search for `sender`'s log: compare the advertiser's
    /// root over `[lo, hi)` to our replica's; descend only if they differ,
    /// pulling records once the range is small (design log-shipping §12).
    fn on_log_range_root(&mut self, sender: NodeId, boot_id: u64, lo: u64, hi: u64, remote_root: Vec<u8>) {
        let replica = self
            .replicas
            .entry(sender)
            .or_insert_with(|| EventLog::new(self.config.log_window_size));
        if replica.range_root(lo, hi) == remote_root {
            return; // this sub-range already agrees — prune
        }
        if hi - lo <= LOG_LEAF_WIDTH {
            self.emit(sender, GossipMessage::LogPull { boot_id, lo, hi });
        } else {
            let mid = lo + (hi - lo) / 2;
            self.emit(sender, GossipMessage::LogRangeQuery { boot_id, lo, hi: mid });
            self.emit(sender, GossipMessage::LogRangeQuery { boot_id, lo: mid, hi });
        }
    }

    /// Records this node has served to replicas (observability/tests).
    pub fn log_records_served(&self) -> usize {
        self.log_records_served
    }

    // -- durable evidence: erasure-coded sealed windows (design §12.4) ---

    /// The erasure scheme this node uses for durable window evidence.
    fn evidence_scheme(&self) -> Option<ErasureScheme> {
        ErasureScheme::new(self.config.evidence_data_shards, self.config.evidence_parity_shards).ok()
    }

    /// The placement policy applied to *newly* sealed windows (from config).
    fn target_policy(&self) -> PlacementPolicy {
        if self.config.evidence_offbox {
            PlacementPolicy::OffBox
        } else {
            PlacementPolicy::FullRoster
        }
    }

    /// The `count` fragment **holders** for a window: a bounded set chosen by
    /// rendezvous hashing over the current roster, *excluding* any node
    /// quarantined at/above `RestrictEvidenceHolding`, and — under
    /// [`PlacementPolicy::OffBox`] — the `subject` itself. Deterministic given
    /// the same roster, policy, and count, so origin and recoverer agree even
    /// across a policy or erasure-scheme change.
    fn eligible_holders(
        &self,
        record_id: [u8; 32],
        subject: NodeId,
        policy: PlacementPolicy,
        count: usize,
    ) -> Vec<NodeId> {
        if count == 0 {
            return Vec::new();
        }
        let roster: Vec<NodeId> = self
            .membership
            .iter()
            .map(|m| m.node_id)
            .filter(|n| {
                !self
                    .quarantine
                    .get(n)
                    .is_some_and(|s| s.restricts_evidence_holding())
            })
            .filter(|n| policy == PlacementPolicy::FullRoster || *n != subject)
            .collect();
        assign_holders(record_id, &roster, count)
    }

    /// Scatter one window's shards across `holders` under `policy`, storing
    /// locally (and counting an ack) when this node is itself a holder. Returns
    /// the set of indices self-acked this way.
    fn scatter(
        &mut self,
        record_id: [u8; 32],
        boot: u64,
        window_id: u64,
        policy: PlacementPolicy,
        holders: &[NodeId],
        fragments: Vec<EvidenceFragment>,
    ) -> HashSet<usize> {
        let mut self_acked = HashSet::new();
        for fragment in fragments {
            let holder = holders[fragment.index % holders.len()];
            let lf = LogFragment {
                node_id: self.id,
                boot_id: boot,
                window_id,
                policy,
                fragment,
            };
            if holder == self.id {
                let index = lf.fragment.index;
                self.held_fragments.entry(record_id).or_default().insert(index, lf);
                self_acked.insert(index);
            } else {
                self.emit(holder, GossipMessage::LogFragmentStore(Box::new(lf)));
            }
        }
        self_acked
    }

    /// Erasure-code the records of one (sealed) own-log window into shards.
    fn encode_window(&self, window_id: u64) -> Option<([u8; 32], Vec<EvidenceFragment>)> {
        let scheme = self.evidence_scheme()?;
        let size = self.config.log_window_size;
        let lo = window_id.saturating_mul(size);
        let hi = lo.saturating_add(size);
        let records = self.own_log.records_in(lo, hi);
        if records.is_empty() {
            return None;
        }
        let payload = encode_records(&records);
        let record_id = evidence::payload_hash(&payload);
        let fragments = scheme.encode(record_id, &payload).ok()?;
        Some((record_id, fragments))
    }

    /// On each tick (when `evidence_replication` is on), erasure-code any newly
    /// *sealed* own-log window and scatter its shards to the assigned holders —
    /// bounded fan-out durable evidence, not a full copy on every peer.
    fn ship_sealed_windows(&mut self, _now: u64) {
        if !self.config.evidence_replication || self.own_log.is_empty() {
            return;
        }
        let Some(scheme) = self.evidence_scheme() else {
            return;
        };
        let size = self.config.log_window_size;
        let boot = self.config.boot_id;
        let policy = self.target_policy();
        let max_seq = self.own_log.max_sequence();
        for window_id in self.own_log.windows() {
            let key = (boot, window_id);
            if self.shipped_windows.contains_key(&key) {
                continue; // already shipped — sealed windows are immutable
            }
            let hi = window_id.saturating_mul(size).saturating_add(size);
            if max_seq + 1 < hi {
                continue; // window not yet sealed
            }
            let Some((record_id, fragments)) = self.encode_window(window_id) else {
                continue;
            };
            let holders = self.eligible_holders(record_id, self.id, policy, scheme.total());
            if holders.is_empty() {
                continue;
            }
            self.shipped_windows.insert(
                key,
                ShippedWindow {
                    record_id,
                    scheme,
                    policy,
                    holders: holders.clone(),
                    acked: HashSet::new(),
                    migrating: None,
                },
            );
            // One shard per holder, round-robin if there are fewer holders
            // than shards (a small mesh); distinct holders in a large one.
            let self_acked = self.scatter(record_id, boot, window_id, policy, &holders, fragments);
            if let Some(sw) = self.shipped_windows.get_mut(&key) {
                sw.acked.extend(self_acked);
            }
        }
    }

    /// Bleed already-shipped windows from their committed policy over to the
    /// current target policy, a few at a time. A window is **re-shipped** to
    /// its new holder set first; only once that new placement is durable do we
    /// cut over and tell the old-only holders to drop their shards — so a
    /// window is never below its reconstruction threshold mid-migration.
    fn migrate_windows(&mut self, _now: u64) {
        if !self.config.evidence_replication || self.config.evidence_migration_rate == 0 {
            return;
        }
        let target = self.target_policy();
        let Some(scheme) = self.evidence_scheme() else {
            return;
        };

        // 1) Cut over any in-flight migration whose new placement is durable
        //    (judged against the *new* scheme's reconstruction threshold).
        let ready: Vec<(u64, u64)> = self
            .shipped_windows
            .iter()
            .filter(|(_, w)| {
                w.migrating
                    .as_ref()
                    .is_some_and(|m| m.acked.len() >= m.scheme.data)
            })
            .map(|(k, _)| *k)
            .collect();
        for key in ready {
            self.cut_over(key);
        }

        // 2) Start new migrations, bounded so at most `rate` run concurrently.
        //    A window needs migration if its committed policy *or* erasure
        //    scheme differs from the current target (so a parity bump migrates
        //    just like a policy flip).
        let in_flight = self
            .shipped_windows
            .values()
            .filter(|w| w.migrating.is_some())
            .count();
        let budget = self.config.evidence_migration_rate.saturating_sub(in_flight);
        if budget == 0 {
            return;
        }
        let to_start: Vec<(u64, u64, [u8; 32])> = self
            .shipped_windows
            .iter()
            .filter(|(_, w)| {
                w.migrating.is_none() && (w.policy != target || w.scheme != scheme)
            })
            .map(|(k, w)| (k.0, k.1, w.record_id))
            .take(budget)
            .collect();
        for (boot_id, window_id, record_id) in to_start {
            let new_holders = self.eligible_holders(record_id, self.id, target, scheme.total());
            let Some((rid, fragments)) = self.encode_window(window_id) else {
                continue;
            };
            debug_assert_eq!(rid, record_id, "window content is immutable once sealed");
            if new_holders.is_empty() {
                continue;
            }
            // Re-ship to the new holders (does not touch the committed copy).
            let self_acked =
                self.scatter(record_id, boot_id, window_id, target, &new_holders, fragments);
            if let Some(sw) = self.shipped_windows.get_mut(&(boot_id, window_id)) {
                sw.migrating = Some(Migration {
                    to: target,
                    scheme,
                    holders: new_holders,
                    acked: self_acked,
                });
            }
        }
    }

    /// Commit a window's in-flight migration: adopt the new holders/policy and
    /// tell holders that are no longer assigned to drop their (now stale) shard.
    fn cut_over(&mut self, key: (u64, u64)) {
        let Some(sw) = self.shipped_windows.get_mut(&key) else {
            return;
        };
        let Some(migration) = sw.migrating.take() else {
            return;
        };
        let record_id = sw.record_id;
        let old_holders = std::mem::take(&mut sw.holders);
        sw.policy = migration.to;
        sw.scheme = migration.scheme;
        sw.holders = migration.holders;
        sw.acked = migration.acked;
        let new_set: HashSet<NodeId> = sw.holders.iter().copied().collect();
        let drop_targets: Vec<NodeId> = old_holders
            .into_iter()
            .filter(|h| !new_set.contains(h))
            .collect();
        for target in drop_targets {
            if target == self.id {
                self.held_fragments.remove(&record_id);
            } else {
                self.emit(target, GossipMessage::LogFragmentDrop { record_id });
            }
        }
    }

    /// As a holder: store a shard and return a signed receipt to the origin.
    fn on_fragment_store(&mut self, sender: NodeId, lf: LogFragment) {
        if !lf.fragment.integrity_ok() {
            return; // corrupted in flight — drop it
        }
        let receipt = EvidenceReceipt::sign(&self.keypair, self.id, &lf.fragment, self.tick);
        let record_id = lf.fragment.record_id;
        let index = lf.fragment.index;
        self.held_fragments.entry(record_id).or_default().insert(index, lf);
        self.emit(sender, GossipMessage::LogFragmentAck(Box::new(receipt)));
    }

    /// As a holder: drop shards for a record whose placement was superseded by
    /// a completed migration.
    fn on_fragment_drop(&mut self, record_id: [u8; 32]) {
        self.held_fragments.remove(&record_id);
    }

    /// As an origin: record a holder's acknowledgement, advancing the tracked
    /// durability of the committed placement and/or an in-flight migration.
    fn on_fragment_ack(&mut self, sender: NodeId, receipt: EvidenceReceipt) {
        let Some(member) = self.membership.get(&sender) else {
            return;
        };
        if receipt.holder != sender || !receipt.verify(&member.public_key) {
            return; // forged or misattributed receipt
        }
        for sw in self.shipped_windows.values_mut() {
            if sw.record_id == receipt.record_id {
                if sw.holders.contains(&sender) {
                    sw.acked.insert(receipt.fragment_index);
                }
                if let Some(m) = &mut sw.migrating {
                    if m.holders.contains(&sender) {
                        m.acked.insert(receipt.fragment_index);
                    }
                }
                break;
            }
        }
    }

    /// As a holder: answer a reconstruction request with the shard(s) we hold.
    fn on_fragment_request(&mut self, sender: NodeId, record_id: [u8; 32]) {
        let frags: Vec<LogFragment> = self
            .held_fragments
            .get(&record_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        for lf in frags {
            self.emit(sender, GossipMessage::LogFragmentReply(Box::new(lf)));
        }
    }

    /// As a recoverer: gather a returned shard and, once a reconstruction
    /// threshold is in hand, rebuild the window — verifying it against the
    /// record id — and fold the records into our replica of the origin's log.
    fn on_fragment_reply(&mut self, _sender: NodeId, lf: LogFragment) {
        if !lf.fragment.integrity_ok() {
            return;
        }
        let record_id = lf.fragment.record_id;
        if self.recovered.contains(&record_id) {
            return; // already rebuilt
        }
        let threshold = lf.fragment.threshold;
        let node_id = lf.node_id;
        {
            let entry = self.gathering.entry(record_id).or_default();
            entry.insert(lf.fragment.index, lf);
            if entry.len() < threshold {
                return; // not enough shards yet
            }
        }
        let frags: Vec<EvidenceFragment> = self
            .gathering
            .get(&record_id)
            .map(|m| m.values().map(|f| f.fragment.clone()).collect())
            .unwrap_or_default();
        if let Ok(payload) = erasure::reconstruct(&frags) {
            if evidence::payload_hash(&payload) == record_id {
                if let Ok(records) = decode_records(&payload) {
                    let replica = self
                        .replicas
                        .entry(node_id)
                        .or_insert_with(|| EventLog::new(self.config.log_window_size));
                    for r in records {
                        replica.append(r);
                    }
                    self.recovered.insert(record_id);
                }
            }
        }
        self.gathering.remove(&record_id);
    }

    /// Begin reconstructing a window's records from its holders, using the
    /// window's *self-describing* [`WindowPlacement`] to find them — so a
    /// recoverer replays the exact holder set the origin used, regardless of
    /// the mesh's current policy. Seeded with any shard we already hold; the
    /// rebuilt records land in our replica once a threshold of shards returns.
    pub fn request_reconstruction(&mut self, placement: &WindowPlacement) {
        let holders = self.eligible_holders(
            placement.record_id,
            placement.subject,
            placement.policy,
            placement.holder_count,
        );
        let mine: Vec<LogFragment> = self
            .held_fragments
            .get(&placement.record_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        for lf in mine {
            self.on_fragment_reply(self.id, lf);
        }
        for holder in holders {
            self.emit(
                holder,
                GossipMessage::LogFragmentRequest {
                    record_id: placement.record_id,
                },
            );
        }
    }

    /// The self-describing placement of a sealed window this node shipped, if
    /// any — the handle a recoverer/auditor needs to find its holders.
    pub fn window_placement(&self, boot_id: u64, window_id: u64) -> Option<WindowPlacement> {
        self.shipped_windows.get(&(boot_id, window_id)).map(|w| WindowPlacement {
            record_id: w.record_id,
            subject: self.id,
            boot_id,
            window_id,
            policy: w.policy,
            holder_count: w.scheme.total(),
        })
    }

    /// The record id of a sealed window this node erasure-shipped, if any.
    pub fn shipped_record_id(&self, boot_id: u64, window_id: u64) -> Option<[u8; 32]> {
        self.shipped_windows.get(&(boot_id, window_id)).map(|w| w.record_id)
    }

    /// A shipped window's durability: acknowledged shards / reconstruction
    /// threshold (`>= 1.0` means it can still be rebuilt). `None` if not
    /// shipped from this node.
    pub fn window_durability(&self, boot_id: u64, window_id: u64) -> Option<f64> {
        self.shipped_windows
            .get(&(boot_id, window_id))
            .map(|w| erasure::durability(w.acked.len(), w.scheme.data))
    }

    /// Whether a shipped window is currently migrating to a new placement.
    pub fn is_migrating(&self, boot_id: u64, window_id: u64) -> bool {
        self.shipped_windows
            .get(&(boot_id, window_id))
            .is_some_and(|w| w.migrating.is_some())
    }

    /// Number of distinct shards this node stores for `record_id` (as a holder).
    pub fn held_fragment_count(&self, record_id: [u8; 32]) -> usize {
        self.held_fragments.get(&record_id).map(|m| m.len()).unwrap_or(0)
    }

    /// Whether this node has reconstructed `record_id` from holders.
    pub fn has_recovered(&self, record_id: [u8; 32]) -> bool {
        self.recovered.contains(&record_id)
    }

    /// The assigned fragment holders for a window placement (deterministic;
    /// ops/tests).
    pub fn fragment_holders(&self, placement: &WindowPlacement) -> Vec<NodeId> {
        self.eligible_holders(
            placement.record_id,
            placement.subject,
            placement.policy,
            placement.holder_count,
        )
    }

    /// Retarget durable-evidence placement at runtime: the policy applied to
    /// new windows (`offbox`), the erasure `parity` paired with it (bump this
    /// alongside `OffBox` to offset the lost holder candidate in small meshes),
    /// and how many already-shipped windows may migrate at once. This is the
    /// safe "flip the flag" entry point — old windows keep their recorded
    /// policy/scheme and stay reconstructable throughout the migration, which
    /// re-ships them under the new policy *and* parity before dropping the old.
    pub fn set_evidence_placement(&mut self, offbox: bool, parity: usize, migration_rate: usize) {
        self.config.evidence_offbox = offbox;
        self.config.evidence_parity_shards = parity;
        self.config.evidence_migration_rate = migration_rate;
    }

    pub fn current_tick(&self) -> u64 {
        self.tick
    }

    /// Drain queued outbound messages.
    pub fn take_outbox(&mut self) -> Vec<Addressed> {
        std::mem::take(&mut self.outbox)
    }

    // -- the SWIM tick --------------------------------------------------

    /// Advance one logical tick.
    pub fn tick(&mut self) {
        self.tick += 1;
        let now = self.tick;

        self.expire_suspicions(now);
        self.advance_probe(now);
        self.drop_stale_owed(now);
        self.run_witness_duties(now);
        self.advertise_logs(now);
        self.ship_sealed_windows(now);
        self.migrate_windows(now);

        // Start a new direct probe on the interval if idle.
        if self.pending.is_none() && now.is_multiple_of(self.config.probe_interval) {
            if let Some(target) = self.next_probe_target() {
                self.pending = Some(PendingProbe {
                    target,
                    stage: ProbeStage::Direct,
                    stage_tick: now,
                });
                self.emit(target, GossipMessage::Ping);
            }
        }
    }

    /// Confirm `Faulty` any member that has been `Suspect` past the timeout.
    fn expire_suspicions(&mut self, now: u64) {
        let timed_out: Vec<NodeId> = self
            .membership
            .others()
            .filter(|m| {
                m.liveness == LivenessState::Suspect
                    && now.saturating_sub(m.last_change_tick) >= self.config.suspicion_timeout
            })
            .map(|m| m.node_id)
            .collect();
        for id in timed_out {
            // The confirmed-faulty update will ride out on the next emit's
            // piggyback; broadcast it proactively to all alive peers too.
            if self.membership.confirm_faulty(&id, now).is_some() {
                self.broadcast_membership();
            }
        }
    }

    /// Advance the in-flight probe across its stages.
    fn advance_probe(&mut self, now: u64) {
        let Some(p) = &self.pending else {
            return;
        };
        let target = p.target;
        let stage = p.stage;
        let stage_tick = p.stage_tick;
        // Each stage is given one tick to be answered by the settle loop.
        if now.saturating_sub(stage_tick) < 1 {
            return;
        }
        match stage {
            ProbeStage::Direct => {
                // No direct ACK arrived: escalate to indirect probes.
                let peers = self.indirect_peers(target);
                if peers.is_empty() {
                    self.begin_suspect(target, now);
                } else {
                    if let Some(pp) = &mut self.pending {
                        pp.stage = ProbeStage::Indirect;
                        pp.stage_tick = now;
                    }
                    for peer in peers {
                        self.emit(peer, GossipMessage::PingReq { target });
                    }
                }
            }
            ProbeStage::Indirect => {
                // No indirect vouch arrived either: suspect the target.
                self.begin_suspect(target, now);
            }
        }
    }

    fn begin_suspect(&mut self, target: NodeId, now: u64) {
        self.pending = None;
        if self.membership.suspect(&target, now).is_some() {
            self.broadcast_membership();
        }
    }

    fn drop_stale_owed(&mut self, now: u64) {
        self.owed.retain(|o| now.saturating_sub(o.tick) < 2);
    }

    /// Round-robin the next alive peer to probe.
    fn next_probe_target(&mut self) -> Option<NodeId> {
        let candidates: Vec<NodeId> = self
            .membership
            .others()
            .filter(|m| matches!(m.liveness, LivenessState::Alive | LivenessState::Suspect))
            .map(|m| m.node_id)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let pick = candidates[self.probe_cursor % candidates.len()];
        self.probe_cursor = self.probe_cursor.wrapping_add(1);
        Some(pick)
    }

    fn indirect_peers(&self, target: NodeId) -> Vec<NodeId> {
        self.membership
            .others()
            .filter(|m| m.node_id != target && m.liveness == LivenessState::Alive)
            .take(self.config.indirect_k)
            .map(|m| m.node_id)
            .collect()
    }

    // -- inbound handling -----------------------------------------------

    /// Process one inbound envelope. Invalid envelopes are dropped silently
    /// (a real deployment would also record a suspicion signal).
    pub fn deliver(&mut self, env: GossipEnvelope) {
        if !self.accept(&env) {
            return;
        }
        let now = self.tick;
        // Hearing from the sender at all is evidence of liveness.
        if self.membership.confirm_alive(&env.sender, now).is_some() {
            self.broadcast_membership();
        }
        // Merge piggybacked membership under SWIM precedence; refute any
        // suspicion of ourselves.
        let mut refute = false;
        for u in &env.piggyback {
            if u.node_id == self.id {
                if !matches!(u.liveness, LivenessState::Alive) && u.incarnation >= self.membership.my_incarnation() {
                    refute = true;
                }
                continue;
            }
            self.membership.apply(u, now);
        }
        if refute {
            self.membership.refute(now);
            self.broadcast_membership();
        }

        match env.message.clone() {
            GossipMessage::Ping => {
                self.emit(env.sender, GossipMessage::Ack);
            }
            GossipMessage::Ack => self.on_ack(env.sender, now),
            GossipMessage::PingReq { target } => {
                self.owed.push(OwedIndirect {
                    requester: env.sender,
                    target,
                    tick: now,
                });
                self.emit(target, GossipMessage::Ping);
            }
            GossipMessage::PingReqAck { target, alive } => {
                if alive {
                    if let Some(p) = &self.pending {
                        if p.target == target {
                            self.pending = None;
                            self.membership.confirm_alive(&target, now);
                        }
                    }
                }
            }
            GossipMessage::AttestChallenge(ch) => self.on_challenge(ch, now),
            GossipMessage::AttestEvidence(ev) => self.on_evidence(*ev, now),
            GossipMessage::AttestResult(res) => {
                // A witness's verdict: record it and re-aggregate the
                // subject's trust from its assigned witnesses.
                self.record_report(res.subject, res.verifier, res.result);
                self.aggregate_trust(res.subject);
            }
            GossipMessage::LogDigest(ad) => self.on_log_digest(env.sender, ad, now),
            GossipMessage::LogRangeQuery { boot_id, lo, hi } => {
                // Answer with our own log's root over the queried range.
                if boot_id == self.config.boot_id {
                    let root = self.own_log.range_root(lo, hi);
                    self.emit(env.sender, GossipMessage::LogRangeRoot { boot_id, lo, hi, root });
                }
            }
            GossipMessage::LogRangeRoot { boot_id, lo, hi, root } => {
                self.on_log_range_root(env.sender, boot_id, lo, hi, root);
            }
            GossipMessage::LogPull { boot_id, lo, hi } => {
                // Serve our own log's records in the requested (leaf) range.
                if boot_id == self.config.boot_id {
                    let records = self.own_log.records_in(lo, hi);
                    if !records.is_empty() {
                        self.log_records_served += records.len();
                        self.emit(env.sender, GossipMessage::LogRecords(records));
                    }
                }
            }
            GossipMessage::LogRecords(records) => {
                for r in records {
                    self.replicas
                        .entry(r.node_id)
                        .or_insert_with(|| EventLog::new(self.config.log_window_size))
                        .append(r);
                }
            }
            GossipMessage::LogFragmentStore(lf) => self.on_fragment_store(env.sender, *lf),
            GossipMessage::LogFragmentAck(receipt) => self.on_fragment_ack(env.sender, *receipt),
            GossipMessage::LogFragmentRequest { record_id } => {
                self.on_fragment_request(env.sender, record_id)
            }
            GossipMessage::LogFragmentReply(lf) => self.on_fragment_reply(env.sender, *lf),
            GossipMessage::LogFragmentDrop { record_id } => self.on_fragment_drop(record_id),
        }
    }

    /// Validate an envelope's mesh, signature, and sender membership.
    fn accept(&self, env: &GossipEnvelope) -> bool {
        if env.mesh_id != self.mesh_id {
            return false;
        }
        if !env.verify_signature() {
            return false;
        }
        // The sender must be a known member and present the key we know.
        match self.membership.get(&env.sender) {
            Some(m) => m.public_key == env.sender_public_key,
            None => false,
        }
    }

    fn on_ack(&mut self, sender: NodeId, now: u64) {
        // Direct probe satisfied?
        if let Some(p) = &self.pending {
            if p.target == sender {
                self.pending = None;
            }
        }
        // Fulfill any indirect probes we owed for this target.
        let fulfilled: Vec<NodeId> = self
            .owed
            .iter()
            .filter(|o| o.target == sender)
            .map(|o| o.requester)
            .collect();
        self.owed.retain(|o| o.target != sender);
        for requester in fulfilled {
            self.emit(
                requester,
                GossipMessage::PingReqAck {
                    target: sender,
                    alive: true,
                },
            );
        }
        self.membership.confirm_alive(&sender, now);
    }

    // -- attestation ----------------------------------------------------

    /// Issue a fresh, nonce-bound attestation challenge to `target`.
    pub fn challenge_peer(&mut self, target: NodeId) {
        let now = self.tick;
        let nonce = self.make_nonce(target);
        let ch = AttestationChallenge {
            challenger: self.id,
            subject: target,
            nonce,
            pcr_bank: self.config.pcr_bank.clone(),
            pcr_selection: self.config.pcr_selection.clone(),
            policy_revision: self.config.policy_revision,
            expires_at_tick: now + 5,
        };
        self.issued_challenges.push(ch.clone());
        self.emit(target, GossipMessage::AttestChallenge(ch));
    }

    fn on_challenge(&mut self, ch: AttestationChallenge, now: u64) {
        if ch.subject != self.id || now > ch.expires_at_tick {
            return;
        }
        if let Ok(ev) =
            self.attestor
                .produce(&ch, self.config.policy_revision, None, self.endorsement.clone(), now)
        {
            self.emit(ch.challenger, GossipMessage::AttestEvidence(Box::new(ev)));
        }
    }

    fn on_evidence(&mut self, ev: crate::types::AttestationEvidence, now: u64) {
        // Match to a challenge we issued for this subject.
        let Some(pos) = self
            .issued_challenges
            .iter()
            .position(|c| c.subject == ev.subject && c.nonce == ev.challenge_nonce)
        else {
            return;
        };
        let ch = self.issued_challenges.remove(pos);
        let result = self
            .attestor
            .verify(
                &ch,
                &ev,
                &self.peer_reference,
                &self.anchors,
                self.id,
                now,
                self.config.reference_match,
                self.config.retired_action,
            );
        let verdict = result.result;
        // Our own direct observation — provisional until (and unless) the
        // assigned-witness quorum decides otherwise in `aggregate_trust`.
        self.membership.set_trust(&ev.subject, verdict_to_trust(verdict));
        self.record_report(ev.subject, self.id, verdict);
        self.aggregate_trust(ev.subject);
        // Gossip the signed verdict so every node aggregates the same
        // witness quorum (design §9.1, §11.4).
        self.broadcast(GossipMessage::AttestResult(result));
    }

    // -- witness duties + trust aggregation (design §10, §11) -----------

    /// The full set of node ids this node knows (its witness roster).
    fn roster(&self) -> Vec<NodeId> {
        self.membership.iter().map(|m| m.node_id).collect()
    }

    /// The witness set assigned to `subject` under the current roster/epoch.
    fn witnesses_for(&self, subject: NodeId) -> witness::WitnessSet {
        witness::assign(
            subject,
            &self.roster(),
            Epoch(self.config.mesh_epoch),
            self.config.witness_count,
        )
    }

    /// As an assigned witness, periodically (re-)challenge the alive subjects
    /// this node is responsible for.
    fn run_witness_duties(&mut self, now: u64) {
        if self.config.witness_count == 0 {
            return;
        }
        let roster = self.roster();
        let epoch = Epoch(self.config.mesh_epoch);
        let k = self.config.witness_count;
        let me = self.id;
        let interval = self.config.attestation_interval;
        let due: Vec<NodeId> = self
            .membership
            .others()
            .filter(|m| matches!(m.liveness, LivenessState::Alive))
            .map(|m| m.node_id)
            .filter(|s| witness::is_witness(me, *s, &roster, epoch, k))
            .filter(|s| {
                self.last_challenge
                    .get(s)
                    .is_none_or(|t| now.saturating_sub(*t) >= interval)
            })
            .collect();
        for subject in due {
            self.last_challenge.insert(subject, now);
            self.challenge_peer(subject);
        }
    }

    fn record_report(&mut self, subject: NodeId, verifier: NodeId, verdict: Verdict) {
        self.witness_reports
            .entry(subject)
            .or_default()
            .insert(verifier, verdict);
    }

    /// Decide `subject`'s trust from the verdicts of its *assigned* witnesses
    /// once a quorum has reported (design §11.4). Below quorum, leave the
    /// existing (provisional / direct-observation) trust untouched.
    fn aggregate_trust(&mut self, subject: NodeId) {
        // A quarantined node's trust is frozen until a rejoin explicitly
        // lifts the quarantine — re-attesting alone must not auto-clear it.
        if self.quarantine.contains_key(&subject) {
            return;
        }
        let ws = self.witnesses_for(subject);
        let relevant: Vec<Verdict> = match self.witness_reports.get(&subject) {
            Some(reports) => ws
                .witnesses
                .iter()
                .filter_map(|w| reports.get(w).copied())
                .collect(),
            None => return,
        };
        let reported = relevant.len();
        if reported == 0 || reported < ws.quorum_threshold {
            return;
        }
        let fails = relevant.iter().filter(|v| matches!(v, Verdict::Fail)).count();
        let passes = relevant.iter().filter(|v| matches!(v, Verdict::Pass)).count();
        // Is the subject still serving its probation window?
        let on_probation = matches!(
            self.membership.get(&subject).map(|m| m.trust),
            Some(TrustState::Probationary) | Some(TrustState::ProvisionallyAdmitted)
        );
        let probation_elapsed = self
            .probation_start
            .get(&subject)
            .is_none_or(|start| self.tick.saturating_sub(*start) >= self.config.probation_period);

        // ≥1/3 critical objections → Suspicious; else ≥80% pass → Trusted
        // (but a probationer is only *promoted* once its window elapses);
        // ≥60% → Degraded; otherwise withhold trust as Suspicious.
        let trust = if fails * 3 >= reported {
            TrustState::Suspicious
        } else if passes * 5 >= reported * 4 {
            if on_probation && !probation_elapsed {
                TrustState::Probationary // passing, but not yet promotable
            } else {
                TrustState::Trusted
            }
        } else if passes * 5 >= reported * 3 {
            if on_probation {
                TrustState::Probationary
            } else {
                TrustState::Degraded
            }
        } else {
            TrustState::Suspicious
        };
        if trust == TrustState::Trusted {
            self.probation_start.remove(&subject);
        }
        self.membership.set_trust(&subject, trust);
    }

    /// How `subject`'s assigned witnesses currently vote (dashboard §17.4).
    pub fn witness_summary(&self, subject: NodeId) -> WitnessSummary {
        let ws = self.witnesses_for(subject);
        let (mut pass, mut fail, mut reported) = (0usize, 0usize, 0usize);
        if let Some(reports) = self.witness_reports.get(&subject) {
            for w in &ws.witnesses {
                if let Some(v) = reports.get(w) {
                    reported += 1;
                    match v {
                        Verdict::Pass => pass += 1,
                        Verdict::Fail => fail += 1,
                        _ => {}
                    }
                }
            }
        }
        WitnessSummary {
            subject,
            assigned: ws.witnesses.len(),
            reported,
            pass,
            fail,
            quorum: ws.quorum_threshold,
        }
    }

    /// Expose this node's witness assignment for `subject` (testing / ops).
    pub fn assigned_witnesses(&self, subject: NodeId) -> Vec<NodeId> {
        self.witnesses_for(subject).witnesses
    }

    // -- enrollment (design §7) -----------------------------------------

    /// Fingerprint of this node's mesh key — its attestation identity for
    /// duplicate-detection during enrollment.
    pub fn ak_fingerprint(&self) -> [u8; 32] {
        self.keypair.public().fingerprint()
    }

    /// As a joining candidate, answer an [`EnrollmentChallenge`] with a
    /// signed, nonce-bound [`EnrollmentClaim`].
    pub fn make_enrollment_claim(
        &self,
        challenge: &EnrollmentChallenge,
        role: &str,
        agent_version: &str,
    ) -> anyhow::Result<EnrollmentClaim> {
        let ach = AttestationChallenge {
            challenger: self.id,
            subject: self.id,
            nonce: challenge.nonce.clone(),
            pcr_bank: challenge.pcr_bank.clone(),
            pcr_selection: challenge.pcr_selection.clone(),
            policy_revision: challenge.policy_revision,
            expires_at_tick: self.tick + 5,
        };
        let evidence =
            self.attestor
                .produce(
                    &ach,
                    self.config.policy_revision,
                    Some(agent_version.to_string()),
                    self.endorsement.clone(),
                    self.tick,
                )?;
        Ok(EnrollmentClaim::create(
            &self.keypair,
            challenge.mesh_id.clone(),
            self.id,
            self.ak_fingerprint(),
            role,
            agent_version,
            challenge.nonce.clone(),
            evidence,
            self.tick,
        ))
    }

    /// As an admission witness, assess a candidate's claim and cast a signed
    /// [`EnrollmentVote`] (design §7.4 steps 7–8).
    pub fn vote_on_enrollment(
        &self,
        claim: &EnrollmentClaim,
        challenge: &EnrollmentChallenge,
        tick: u64,
    ) -> EnrollmentVote {
        let reason = self.assess_claim(claim, challenge, tick);
        let verdict = if reason == AdmissionReason::Ok {
            AdmissionVerdict::Approve
        } else {
            AdmissionVerdict::Reject
        };
        EnrollmentVote::sign(&self.keypair, self.id, claim.candidate, verdict, reason, tick)
    }

    fn assess_claim(
        &self,
        claim: &EnrollmentClaim,
        challenge: &EnrollmentChallenge,
        tick: u64,
    ) -> AdmissionReason {
        if !claim.verify_signature() {
            return AdmissionReason::BadSignature;
        }
        if claim.nonce != challenge.nonce {
            return AdmissionReason::NonceMismatch;
        }
        // Duplicate/cloned identity: the candidate's fingerprint must not
        // already belong to a known member.
        let existing: Vec<[u8; 32]> =
            self.membership.iter().map(|m| m.public_key.fingerprint()).collect();
        if enrollment::is_duplicate_identity(&claim.ak_fingerprint, &existing) {
            return AdmissionReason::DuplicateIdentity;
        }
        // Measured-state attestation against our golden reference.
        let ach = AttestationChallenge {
            challenger: self.id,
            subject: claim.candidate,
            nonce: challenge.nonce.clone(),
            pcr_bank: challenge.pcr_bank.clone(),
            pcr_selection: challenge.pcr_selection.clone(),
            policy_revision: challenge.policy_revision,
            expires_at_tick: tick + 5,
        };
        let result = self
            .attestor
            .verify(
                &ach,
                &claim.evidence,
                &self.peer_reference,
                &self.anchors,
                self.id,
                tick,
                self.config.reference_match,
                self.config.retired_action,
            );
        if result.reason_codes.contains(&ReasonCode::AkUntrusted) {
            return AdmissionReason::AkUntrusted;
        }
        if result.result != Verdict::Pass {
            return AdmissionReason::AttestationFailed;
        }
        AdmissionReason::Ok
    }

    /// Admit a node into this view as **probationary**: learn it and start
    /// its probation clock (design §7.5).
    pub fn admit_probationary(
        &mut self,
        node_id: NodeId,
        key: crate::crypto::MeshPublicKey,
        role: &str,
        tick: u64,
    ) {
        self.membership.learn(node_id, key, role, tick);
        self.membership.set_trust(&node_id, TrustState::Probationary);
        self.probation_start.insert(node_id, tick);
    }

    // -- quarantine (design §13) ----------------------------------------

    /// Propose quarantining `subject` at `scope`, citing a reason if this
    /// node currently considers the subject suspicious.
    pub fn propose_quarantine(
        &self,
        subject: NodeId,
        scope: QuarantineScope,
        tick: u64,
    ) -> QuarantineProposal {
        let reasons = if matches!(
            self.membership.get(&subject).map(|m| m.trust),
            Some(TrustState::Suspicious)
        ) {
            vec![ReasonCode::PcrMismatch]
        } else {
            Vec::new()
        };
        QuarantineProposal::create(&self.keypair, self.id, subject, reasons, scope, tick + 10, tick)
    }

    /// Vote on a quarantine proposal: approve if this node independently sees
    /// the subject as suspicious or already isolated; reject otherwise.
    pub fn vote_on_quarantine(&self, proposal: &QuarantineProposal, tick: u64) -> QuarantineVote {
        let ballot = if matches!(
            self.membership.get(&proposal.subject).map(|m| m.trust),
            Some(TrustState::Suspicious) | Some(TrustState::Isolated)
        ) {
            Ballot::Approve
        } else {
            Ballot::Reject
        };
        QuarantineVote::sign(&self.keypair, self.id, proposal.id, ballot, tick)
    }

    /// Apply an enacted quarantine scope to `subject` in this view.
    pub fn apply_quarantine(&mut self, subject: NodeId, scope: QuarantineScope, _tick: u64) {
        self.quarantine.insert(subject, scope);
        if scope.isolates() {
            self.membership.set_trust(&subject, TrustState::Isolated);
        }
    }

    /// The scope currently quarantining `subject`, if any.
    pub fn quarantine_of(&self, subject: NodeId) -> Option<QuarantineScope> {
        self.quarantine.get(&subject).copied()
    }

    /// Lift a quarantine on rejoin: the node returns to **probation**, never
    /// straight to trusted (design §13.5).
    pub fn lift_quarantine(&mut self, subject: NodeId, tick: u64) {
        self.quarantine.remove(&subject);
        if self.membership.get(&subject).is_some() {
            self.membership.set_trust(&subject, TrustState::Probationary);
            self.probation_start.insert(subject, tick);
        }
    }

    /// As a witness, verify a rejoining node's fresh attestation (signature,
    /// nonce, measured state) — no duplicate check, since it is already a
    /// member re-proving itself.
    pub fn verify_rejoin(
        &self,
        claim: &EnrollmentClaim,
        challenge: &EnrollmentChallenge,
        tick: u64,
    ) -> bool {
        if !claim.verify_signature() || claim.nonce != challenge.nonce {
            return false;
        }
        let ach = AttestationChallenge {
            challenger: self.id,
            subject: claim.candidate,
            nonce: challenge.nonce.clone(),
            pcr_bank: challenge.pcr_bank.clone(),
            pcr_selection: challenge.pcr_selection.clone(),
            policy_revision: challenge.policy_revision,
            expires_at_tick: tick + 5,
        };
        self.attestor
            .verify(
                &ach,
                &claim.evidence,
                &self.peer_reference,
                &self.anchors,
                self.id,
                tick,
                self.config.reference_match,
                self.config.retired_action,
            )
            .result
            == Verdict::Pass
    }

    /// Replace the node's TPM backend (a clean reimage / remediation),
    /// minting a fresh attestation key. Used before a rejoin.
    pub fn replace_backend(&mut self, backend: Box<dyn TpmBackend>) -> anyhow::Result<()> {
        self.attestor = Attestor::new(backend)?;
        Ok(())
    }

    fn make_nonce(&self, target: NodeId) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(&self.id.0);
        h.update(&target.0);
        h.update(&self.tick.to_be_bytes());
        h.update(&self.sequence.to_be_bytes());
        h.finalize().as_bytes()[..16].to_vec()
    }

    // -- emission -------------------------------------------------------

    fn emit(&mut self, to: NodeId, message: GossipMessage) {
        if to == self.id {
            return;
        }
        let envelope = self.build_envelope(message);
        self.outbox.push(Addressed { to, envelope });
    }

    /// Send a message to every alive peer.
    fn broadcast(&mut self, message: GossipMessage) {
        let peers: Vec<NodeId> = self
            .membership
            .others()
            .filter(|m| matches!(m.liveness, LivenessState::Alive | LivenessState::Suspect))
            .map(|m| m.node_id)
            .collect();
        for p in peers {
            let envelope = self.build_envelope(message.clone());
            self.outbox.push(Addressed { to: p, envelope });
        }
    }

    /// Broadcast a bare membership-sync (Ping carries the piggyback digest).
    fn broadcast_membership(&mut self) {
        // A lightweight ALIVE refresh: reuse Ack as a no-op carrier so the
        // piggyback digest propagates without provoking another Ack.
        let peers: Vec<NodeId> = self
            .membership
            .others()
            .filter(|m| matches!(m.liveness, LivenessState::Alive))
            .map(|m| m.node_id)
            .collect();
        for p in peers {
            let envelope = self.build_envelope(GossipMessage::Ack);
            self.outbox.push(Addressed { to: p, envelope });
        }
    }

    fn build_envelope(&mut self, message: GossipMessage) -> GossipEnvelope {
        self.sequence += 1;
        let piggyback = self.membership.digest(self.config.piggyback_limit);
        GossipEnvelope {
            mesh_id: self.mesh_id.clone(),
            sender: self.id,
            sender_public_key: self.keypair.public(),
            sender_incarnation: self.membership.my_incarnation(),
            sequence: self.sequence,
            message,
            piggyback,
            timestamp_tick: self.tick,
            signature: crate::crypto::Signature::zero(),
        }
        .signed(&self.keypair)
    }
}

/// Map an attestation verdict to a trust state (a single observation).
fn verdict_to_trust(v: Verdict) -> TrustState {
    match v {
        Verdict::Pass => TrustState::Trusted,
        Verdict::Warn => TrustState::Degraded,
        Verdict::Fail => TrustState::Suspicious,
        Verdict::Inconclusive => TrustState::Unknown,
    }
}
