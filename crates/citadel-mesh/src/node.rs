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

use crate::application::{AppAttestationResult, AppMeasurement, AppPolicy, AppVerdict};
use crate::attest::{Attestor, ReferenceMeasurements, TrustAnchors};
use crate::crypto::MeshKeypair;
use crate::enrollment::{
    self, AdmissionReason, AdmissionVerdict, EnrollmentChallenge, EnrollmentClaim, EnrollmentVote,
};
use crate::erasure::{self, ErasureScheme, EvidenceFragment};
use crate::evidence::{self, assign_holders, EvidenceReceipt};
use crate::evidence::{EvidenceChain, RecordType};
use crate::id::{Epoch, MeshId, NodeId};
use crate::logship::{
    checkpoint_nonce, decode_records, encode_records, Checkpoint, DigestAdvertisement, EventLog,
    EventRecord, LogFragment, PlacementPolicy,
};
use crate::membership::Membership;
use crate::promotion::{PromotionProposal, PromotionVote};
use crate::quarantine::{Ballot, QuarantineProposal, QuarantineScope, QuarantineVote};
use crate::reference::{
    AcceptedReferences, ArtifactIdentity, BootProfile, FleetArtifactPolicy, PcrClass,
    ReferenceEntry, ReferenceManifest, ReferenceMatchPolicy, RetiredAction, Validity,
};
use crate::state::{LivenessState, TrustState};
use crate::store::Store;
use crate::types::{
    AttestationChallenge, Endorsement, GossipEnvelope, GossipMessage, ReasonCode, Verdict,
};
use crate::witness;
use serde::{Deserialize, Serialize};
use tpm_core::backend::TpmBackend;
use tpm_core::eventlog::BootEventLog;

/// PCR the IMA runtime measurement log extends — where app measurements bind
/// (`application-appraisal.md` P4).
const IMA_PCR: u32 = 10;

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
    /// Observer mode (control-plane ingestion, M0): this node enrols and gossips
    /// but is **excluded from witness assignment**, casts **no counting
    /// verdict**, and enforces no quarantine — it only ingests and verifies the
    /// signed traffic every node sees. Default `false`.
    pub observer: bool,
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
    /// Emit signed, quote-bound checkpoints for sealed log windows (design
    /// §9–10), binding each window root to a TPM quote. `false` keeps the
    /// lighter unsigned `DigestAdvertisement` path only.
    pub checkpoint_enabled: bool,
    /// Ship sealed log windows as erasure-coded fragments to a bounded set of
    /// assigned holders (durable evidence vault; design §12.4) — the default
    /// durability mechanism, which scales (bounded fan-out) where full-window
    /// replication to every peer (N-1) does not. `false` disables the durable
    /// vault (the digest-advertise reconciliation path is independent of it).
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
    /// App failures that roll up to *node* distrust (`application-appraisal.md`
    /// §5.3): if this many distinct apps fail on one node, escalate it to
    /// `Suspicious`. `0` disables threshold escalation (a critical-app failure
    /// still escalates regardless). Default `0` — app failure is report-only.
    pub app_escalation_threshold: usize,
    /// Ticks between advertising this node's adopted reference-manifest set for
    /// anti-entropy (`0` disables); lets a node that missed a gossiped manifest
    /// catch up (design §10.2).
    pub reference_advertise_interval: u64,
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
            observer: false,
            attestation_interval: 4,
            probation_period: 6,
            boot_id: 1,
            log_window_size: 16,
            log_advertise_interval: 5,
            checkpoint_enabled: false,
            evidence_replication: true,
            evidence_data_shards: 3,
            evidence_parity_shards: 2,
            evidence_offbox: false,
            evidence_migration_rate: 0,
            reference_match: ReferenceMatchPolicy::Flexible,
            retired_action: RetiredAction::Fail,
            app_escalation_threshold: 0,
            reference_advertise_interval: 0,
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
    /// Authorities this node trusts to sign reference manifests (design §10.2).
    /// `None` = fall back to `anchors` (one authority for both surfaces);
    /// `Some` = a separate authority set (separation of duties).
    reference_authorities: Option<TrustAnchors>,
    /// Reference manifests this node has adopted, by content id — kept so they
    /// can be re-served for anti-entropy and de-duplicated on re-receipt.
    adopted_manifests: std::collections::BTreeMap<[u8; 32], ReferenceManifest>,
    /// Append-only audit chain of adopted reference manifests (design §10.2).
    reference_audit: EvidenceChain,
    /// Last tick this node advertised its adopted-manifest set.
    last_reference_advert: u64,
    /// Policy for appraising registered applications (report-only; §5).
    app_policy: AppPolicy,
    /// Latest app appraisal heard per `(subject node, app name)` — the gossiped
    /// reports a control plane consumes. Report-only: never affects node trust.
    app_results: HashMap<(NodeId, String), AppAttestationResult>,
    /// Hash-chained audit of app appraisals this node produced.
    app_audit: EvidenceChain,
    /// App-scoped quarantine scope enforced per `(subject node, app name)` —
    /// the graded response (block scheduling / revoke creds) short of node
    /// quarantine (`application-appraisal.md` §5.2).
    app_scopes: HashMap<(NodeId, String), QuarantineScope>,
    /// Nodes escalated to distrust by app-failure policy (§5.3). Sticky: the
    /// platform witness quorum must not silently clear an app escalation.
    app_escalated: HashSet<NodeId>,
    /// Policy for appraising the IMA runtime measurement list (C1). Empty =
    /// report-only.
    runtime_policy: crate::runtime::RuntimePolicy,
    /// This node's current IMA runtime list (ASCII), staged to ship in the
    /// evidence it produces so verifiers appraise what ran (C1). Set from the
    /// OS (`/sys/.../ascii_runtime_measurements`); transient (not persisted).
    staged_ima: Option<Vec<u8>>,
    /// This node's firmware measured-boot log (raw TCG bytes), staged to ship in
    /// evidence and to verify its own `pcr_bound` app measurements (B1). Set from
    /// the OS (`/sys/.../binary_bios_measurements`); transient. When present it
    /// overrides the backend's synthesized log — a real node ships exactly what
    /// its firmware measured.
    staged_event_log: Option<Vec<u8>>,
    /// Nodes escalated to distrust by runtime (IMA) policy — a known-bad file
    /// executed. Sticky like [`Self::app_escalated`]: a clean platform quote
    /// must not silently clear a runtime-integrity failure.
    runtime_escalated: HashSet<NodeId>,
    /// Named boot profiles this node can appraise subjects against (design §10.3).
    profiles: std::collections::BTreeMap<String, BootProfile>,
    /// Which profile each subject is assigned (`node_id → profile name`);
    /// unassigned subjects use the default appraisal (`peer_reference`).
    profile_assignments: std::collections::BTreeMap<NodeId, String>,
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
    /// Verified signed checkpoints heard per `(node, boot, window)` (design
    /// §9–10) — the quote-bound commitment a peer keeps to detect equivocation.
    checkpoints: HashMap<(NodeId, u64, u64), Checkpoint>,
    /// Attributable equivocation proofs: two validly-signed, quote-bound
    /// checkpoints with conflicting roots for one `(node, boot, window)`.
    equivocations: Vec<(Checkpoint, Checkpoint)>,
    /// Root last checkpointed per own `(boot, window)`, so honest sealed windows
    /// are checkpointed once but a forked rewrite re-emits the new root.
    emitted_checkpoints: HashMap<(u64, u64), Vec<u8>>,
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

/// A serializable snapshot of a node's **durable evidence** state (design
/// `distributed-log-shipping-lthash.md` §17): own log, replicated peer logs,
/// held fragments, adopted reference manifests, the reference/app audit chains,
/// app appraisals, sealed-window roots, signed checkpoints, and app scopes.
///
/// Transient state — membership liveness/trust, in-flight probes, in-flight
/// erasure migrations, the reconstruction-gathering buffer — is intentionally
/// excluded: it re-converges via gossip and re-attestation, so trust is
/// re-earned on restart rather than blindly restored.
#[derive(Serialize, Deserialize)]
pub struct NodeSnapshot {
    own_log: EventLog,
    replicas: Vec<(NodeId, EventLog)>,
    held_fragments: Vec<LogFragment>,
    adopted_manifests: Vec<ReferenceManifest>,
    reference_audit: EvidenceChain,
    app_audit: EvidenceChain,
    app_results: Vec<AppAttestationResult>,
    checkpoints: Vec<Checkpoint>,
    sealed_roots: Vec<(NodeId, u64, u64, Vec<u8>)>,
    app_scopes: Vec<(NodeId, String, QuarantineScope)>,
    app_escalated: Vec<NodeId>,
    #[serde(default)]
    runtime_escalated: Vec<NodeId>,
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
        let reference_audit = EvidenceChain::new(id, mesh_id.clone());
        let app_audit = EvidenceChain::new(id, mesh_id.clone());
        let mut membership = membership;
        // Advertise observer-ness so peers exclude this node from witness
        // assignment fleet-wide (M0).
        if config.observer {
            membership.set_my_observer();
        }
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
            reference_authorities: None,
            adopted_manifests: std::collections::BTreeMap::new(),
            reference_audit,
            last_reference_advert: 0,
            app_policy: AppPolicy::new(),
            runtime_policy: crate::runtime::RuntimePolicy::new(),
            runtime_escalated: HashSet::new(),
            staged_ima: None,
            staged_event_log: None,
            app_results: HashMap::new(),
            app_audit,
            app_scopes: HashMap::new(),
            app_escalated: HashSet::new(),
            profiles: std::collections::BTreeMap::new(),
            profile_assignments: std::collections::BTreeMap::new(),
            endorsement: None,
            witness_reports: HashMap::new(),
            last_challenge: HashMap::new(),
            probation_start: HashMap::new(),
            quarantine: HashMap::new(),
            own_log: EventLog::new(config_window),
            replicas: HashMap::new(),
            sealed_roots: HashMap::new(),
            checkpoints: HashMap::new(),
            equivocations: Vec::new(),
            emitted_checkpoints: HashMap::new(),
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

    /// Set how a PCR index is appraised — strict (exact), semantic (deferred to
    /// event-log policy), or volatile (ignored) (design §10.1).
    pub fn set_pcr_class(&mut self, index: u32, class: PcrClass) {
        self.peer_reference.set_pcr_class(index, class);
    }

    /// Install the authorities this node trusts to sign reference manifests
    /// (design §10.2). Separate from the AK-endorsement anchors; if never set,
    /// manifests are judged against those anchors instead.
    pub fn set_reference_authorities(&mut self, authorities: TrustAnchors) {
        self.reference_authorities = Some(authorities);
    }

    /// Install the fleet artifact policy gating artifact-bearing references —
    /// approved channels, version baselines, and revocation denylists (§10.2).
    /// Re-evaluated each appraisal, so adding a denial revokes an already-
    /// accepted state on the next challenge.
    pub fn set_artifact_policy(&mut self, policy: FleetArtifactPolicy) {
        self.peer_reference.set_artifact_policy(policy);
    }

    /// Define (or replace) a named boot profile this node appraises against
    /// (design §10.3).
    pub fn define_profile(&mut self, profile: BootProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Assign `subject` to a boot profile by name. Appraisals of that subject
    /// then use the profile's accepted set / classes / policy instead of the
    /// default.
    pub fn assign_profile(&mut self, subject: NodeId, profile: impl Into<String>) {
        self.profile_assignments.insert(subject, profile.into());
    }

    // -- application appraisal (report-only; design §4-6) ----------------

    /// Install the policy this node uses to appraise registered applications.
    pub fn set_app_policy(&mut self, policy: AppPolicy) {
        self.app_policy = policy;
    }

    /// Set the runtime (IMA) appraisal policy (C1). Empty = report-only.
    pub fn set_runtime_policy(&mut self, policy: crate::runtime::RuntimePolicy) {
        self.runtime_policy = policy;
    }

    /// Stage this node's current IMA runtime list (ASCII) to ship in the
    /// evidence it produces, so verifiers appraise what ran after boot (C1).
    pub fn stage_ima(&mut self, ima_ascii: &str) {
        self.staged_ima = Some(ima_ascii.as_bytes().to_vec());
    }

    /// Stage this node's firmware measured-boot log (raw TCG
    /// `binary_bios_measurements` bytes) to ship in the evidence it produces, so
    /// a verifier replays it against the quote (B1). It also becomes the log this
    /// node verifies its own `pcr_bound` app measurements against. Read from the
    /// OS (`/sys/.../binary_bios_measurements`); transient.
    pub fn stage_event_log(&mut self, event_log: &[u8]) {
        self.staged_event_log = Some(event_log.to_vec());
    }

    /// Appraise a subject's IMA runtime measurement list (the ASCII
    /// `ascii_runtime_measurements`) against the runtime policy and act on it
    /// (C1). Returns the violating files. A **denied** (known-bad) file that
    /// executed escalates the *node* to distrust (sticky, like an app
    /// escalation) — a pristine boot quote must not excuse it. An allowlist
    /// miss (`NotAllowed`) is report-only here: it's reported but does not by
    /// itself flip node trust (lockdown enforcement is a policy choice left to
    /// the control plane), matching the app-appraisal graded response.
    pub fn report_runtime(
        &mut self,
        subject: NodeId,
        ima_ascii: &str,
    ) -> Vec<crate::runtime::RuntimeViolation> {
        use crate::runtime::RuntimeReason;
        let (violations, _skipped) = self.runtime_policy.appraise_ascii(ima_ascii);
        let executed_known_bad = violations.iter().any(|v| v.reason == RuntimeReason::Denied);
        if executed_known_bad {
            self.runtime_escalated.insert(subject);
            self.membership.set_trust(&subject, TrustState::Suspicious);
        }
        violations
    }

    /// Whether `subject` has been escalated to distrust by runtime (IMA) policy.
    pub fn runtime_escalated(&self, subject: NodeId) -> bool {
        self.runtime_escalated.contains(&subject)
    }

    /// Validate a measurement's `pcr_bound` claim against this node's own event
    /// log (P4): a measurement is only treated as bound if its digest actually
    /// appears as an IMA event (PCR 10) in a log that replays — otherwise it is
    /// downgraded to a self-reported (advisory) claim. Turns `pcr_bound` from a
    /// self-asserted flag into a verified fact.
    fn validate_binding(&self, measurement: &AppMeasurement) -> AppMeasurement {
        if !measurement.pcr_bound {
            return measurement.clone();
        }
        // Prefer the firmware log this node staged from its own /sys (B1) — what
        // its firmware actually measured — falling back to the backend's log.
        let log_bytes = match &self.staged_event_log {
            Some(bytes) => Some(bytes.clone()),
            None => self.attestor.backend().read_event_log().ok().flatten(),
        };
        let bound = log_bytes
            .and_then(|bytes| BootEventLog::from_bytes(&bytes).ok())
            .is_some_and(|log| {
                log.contains_measurement(IMA_PCR, &measurement.digest, &self.config.pcr_bank)
            });
        if bound {
            measurement.clone()
        } else {
            AppMeasurement {
                pcr_bound: false,
                ..measurement.clone()
            }
        }
    }

    /// Appraise an application measurement (running on this node) and produce a
    /// signed result — pure, no side effects. The measurement's `pcr_bound`
    /// claim is verified against the event log (P4) before appraisal.
    pub fn appraise_app(&self, measurement: &AppMeasurement) -> AppAttestationResult {
        let measurement = self.validate_binding(measurement);
        AppAttestationResult::create(
            &self.keypair,
            self.id,
            self.id,
            &measurement,
            &self.app_policy,
            self.tick,
        )
    }

    /// Report an application measurement: appraise it, record the signed result
    /// locally (audit + latest-per-app) and gossip it so a control plane can
    /// remediate. Records may escalate to node trust only under the §5.3 policy
    /// (`app_escalation_threshold` / critical apps); by default node trust is
    /// untouched.
    pub fn report_app(&mut self, measurement: &AppMeasurement) -> AppAttestationResult {
        let result = self.appraise_app(measurement);
        self.record_app_result(result.clone());
        self.broadcast(GossipMessage::AppResult(Box::new(result.clone())));
        result
    }

    /// Record a (verified) app result: append to the audit chain, keep the
    /// latest per `(subject, app name)`, and apply §5.3 escalation.
    fn record_app_result(&mut self, result: AppAttestationResult) {
        let subject = result.subject;
        self.app_audit.append(
            subject,
            RecordType::AppAttestationResult,
            result.content_id(),
            self.tick,
            self.config.policy_revision,
        );
        self.app_results
            .insert((subject, result.app.name.clone()), result);
        self.maybe_escalate(subject);
    }

    /// §5.3 escalation: roll an app failure up to *node* trust only when the
    /// platform is implicated — a **critical** app failed, or at least
    /// `app_escalation_threshold` distinct apps failed on the node. Otherwise
    /// app failure is report-only and node trust is untouched.
    fn maybe_escalate(&mut self, subject: NodeId) {
        let failed: Vec<&String> = self
            .app_results
            .iter()
            .filter(|((n, _), r)| *n == subject && r.verdict == AppVerdict::Failed)
            .map(|((_, app), _)| app)
            .collect();
        let critical_failed = failed.iter().any(|a| self.app_policy.is_critical(a));
        let threshold_crossed = self.config.app_escalation_threshold > 0
            && failed.len() >= self.config.app_escalation_threshold;
        if critical_failed || threshold_crossed {
            self.app_escalated.insert(subject);
            self.membership.set_trust(&subject, TrustState::Suspicious);
        }
    }

    /// Handle a gossiped app result: verify the verifier's signature, then
    /// record it. Report-only — never changes node trust.
    fn on_app_result(&mut self, sender: NodeId, result: AppAttestationResult) {
        if result.verifier != sender {
            return;
        }
        let Some(member) = self.membership.get(&sender) else {
            return;
        };
        if !result.verify(&member.public_key) {
            return;
        }
        self.record_app_result(result);
    }

    /// The latest app appraisal heard for `(subject, app_name)`, if any.
    pub fn app_result_for(&self, subject: NodeId, app_name: &str) -> Option<&AppAttestationResult> {
        self.app_results.get(&(subject, app_name.to_string()))
    }

    /// Length of this node's app-appraisal audit chain (testing/ops).
    pub fn app_audit_len(&self) -> usize {
        self.app_audit.len()
    }

    // -- durable persistence (design §17; D2) ---------------------------

    /// Capture a serializable snapshot of this node's durable evidence state.
    pub fn snapshot(&self) -> NodeSnapshot {
        NodeSnapshot {
            own_log: self.own_log.clone(),
            replicas: self.replicas.iter().map(|(k, v)| (*k, v.clone())).collect(),
            held_fragments: self
                .held_fragments
                .values()
                .flat_map(|m| m.values().cloned())
                .collect(),
            adopted_manifests: self.adopted_manifests.values().cloned().collect(),
            reference_audit: self.reference_audit.clone(),
            app_audit: self.app_audit.clone(),
            app_results: self.app_results.values().cloned().collect(),
            checkpoints: self.checkpoints.values().cloned().collect(),
            sealed_roots: self
                .sealed_roots
                .iter()
                .map(|((n, b, w), r)| (*n, *b, *w, r.clone()))
                .collect(),
            app_scopes: self
                .app_scopes
                .iter()
                .map(|((n, a), s)| (*n, a.clone(), *s))
                .collect(),
            app_escalated: self.app_escalated.iter().copied().collect(),
            runtime_escalated: self.runtime_escalated.iter().copied().collect(),
        }
    }

    /// Restore durable evidence state from a snapshot. Rebuilds the in-memory
    /// indices and re-applies adopted manifests to the accepted-reference set
    /// (so appraisal reflects them) without re-auditing — the audit chain is
    /// restored verbatim. Does not touch membership/trust (re-earned via gossip).
    pub fn restore(&mut self, snap: NodeSnapshot) {
        self.own_log = snap.own_log;
        self.replicas = snap.replicas.into_iter().collect();
        self.held_fragments.clear();
        for lf in snap.held_fragments {
            self.held_fragments
                .entry(lf.fragment.record_id)
                .or_default()
                .insert(lf.fragment.index, lf);
        }
        self.adopted_manifests = snap
            .adopted_manifests
            .into_iter()
            .map(|m| (m.content_id(), m))
            .collect();
        // Re-apply manifests to the accepted set (no re-audit; chain restored below).
        for m in self.adopted_manifests.values() {
            self.peer_reference.adopt_manifest(m);
        }
        self.reference_audit = snap.reference_audit;
        self.app_audit = snap.app_audit;
        self.app_results = snap
            .app_results
            .into_iter()
            .map(|r| ((r.subject, r.app.name.clone()), r))
            .collect();
        self.checkpoints = snap
            .checkpoints
            .into_iter()
            .map(|c| ((c.node_id, c.boot_id, c.window_id), c))
            .collect();
        self.sealed_roots = snap
            .sealed_roots
            .into_iter()
            .map(|(n, b, w, r)| ((n, b, w), r))
            .collect();
        self.app_scopes = snap
            .app_scopes
            .into_iter()
            .map(|(n, a, s)| ((n, a), s))
            .collect();
        self.app_escalated = snap.app_escalated.into_iter().collect();
        self.runtime_escalated = snap.runtime_escalated.into_iter().collect();
    }

    /// Storage key for this node's snapshot.
    fn persist_key(&self) -> String {
        format!("node-{}.json", self.id.to_hex())
    }

    /// Persist this node's durable evidence to `store`.
    pub fn persist(&self, store: &dyn Store) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(&self.snapshot())?;
        store.save(&self.persist_key(), &bytes)
    }

    /// Hydrate this node's durable evidence from `store`. Returns whether a
    /// snapshot was found and applied.
    pub fn hydrate(&mut self, store: &dyn Store) -> anyhow::Result<bool> {
        match store.load(&self.persist_key())? {
            Some(bytes) => {
                self.restore(serde_json::from_slice(&bytes)?);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // -- graded app-scoped response (P2; design §5.2) -------------------

    /// Apply an app-scoped quarantine to `(subject, app)` — the graded response
    /// (block scheduling / revoke creds) enacted on a quorum decision.
    pub fn apply_app_scope(&mut self, subject: NodeId, app: &str, scope: QuarantineScope) {
        self.app_scopes.insert((subject, app.to_string()), scope);
    }

    /// Lift an app-scoped quarantine (e.g. after the app is remediated).
    pub fn lift_app_scope(&mut self, subject: NodeId, app: &str) {
        self.app_scopes.remove(&(subject, app.to_string()));
    }

    /// The app-scope currently enforced on `(subject, app)`, if any.
    pub fn app_scope_of(&self, subject: NodeId, app: &str) -> Option<QuarantineScope> {
        self.app_scopes.get(&(subject, app.to_string())).copied()
    }

    /// Enforcement hook: may new workloads of `app` be scheduled on `subject`?
    /// `false` once an app-scope at/above `BlockWorkloadScheduling` is enforced.
    pub fn app_workload_blocked(&self, subject: NodeId, app: &str) -> bool {
        self.app_scope_of(subject, app)
            .is_some_and(|s| s.blocks_workload_scheduling())
    }

    /// Enforcement hook: are `app`'s credentials on `subject` revoked?
    pub fn app_credentials_revoked(&self, subject: NodeId, app: &str) -> bool {
        self.app_scope_of(subject, app)
            .is_some_and(|s| s.revokes_credentials())
    }

    /// The accepted set used for a profile name (the named profile's, or the
    /// default `peer_reference`).
    fn accepted_for_profile(&self, profile: &str) -> &AcceptedReferences {
        if !profile.is_empty() {
            if let Some(p) = self.profiles.get(profile) {
                return &p.accepted;
            }
        }
        &self.peer_reference
    }

    // -- fleet quorum promotion (design §10.3) --------------------------

    /// As a proposer: stage a new measured state for quorum promotion.
    pub fn propose_promotion(
        &self,
        profile: &str,
        index: u32,
        digest: Vec<u8>,
        artifact: Option<ArtifactIdentity>,
        validity: Validity,
        tick: u64,
    ) -> PromotionProposal {
        PromotionProposal::create(
            &self.keypair,
            self.id,
            profile,
            index,
            digest,
            artifact,
            validity,
            tick,
        )
    }

    /// As an eligible peer: vote on a promotion. Approve only if it carries
    /// provenance that this node's policy for the target profile permits — peers
    /// judge the artifact independently, no central "known good".
    pub fn vote_on_promotion(&self, proposal: &PromotionProposal, tick: u64) -> PromotionVote {
        let approve = match &proposal.artifact {
            Some(a) => self
                .accepted_for_profile(&proposal.profile)
                .permits_artifact(a),
            None => false, // cannot vouch for an unattributed state
        };
        PromotionVote::sign(&self.keypair, self.id, proposal.id, approve, tick)
    }

    /// Adopt a quorum-promoted state into the target profile's accepted set and
    /// record it in the audit chain.
    pub fn adopt_promoted_state(&mut self, proposal: &PromotionProposal) {
        let mut entry = ReferenceEntry::new(
            proposal.index,
            proposal.digest.clone(),
            proposal.validity.clone(),
        );
        if let Some(a) = &proposal.artifact {
            entry = entry.with_artifact(a.clone());
        }
        if let Some(p) = self.profiles.get_mut(&proposal.profile) {
            p.accepted.accept(entry);
        } else {
            self.peer_reference.accept(entry);
        }
        self.reference_audit.append(
            self.id,
            RecordType::ReferenceUpdate,
            proposal.id,
            self.tick,
            self.config.policy_revision,
        );
    }

    /// The appraisal inputs for `subject`: its assigned profile's policy, or the
    /// node default (`peer_reference` + config) when unassigned/unknown.
    fn appraisal_for(
        &self,
        subject: NodeId,
    ) -> (&AcceptedReferences, ReferenceMatchPolicy, RetiredAction) {
        if let Some(name) = self.profile_assignments.get(&subject) {
            if let Some(p) = self.profiles.get(name) {
                return (&p.accepted, p.match_policy, p.retired_action);
            }
        }
        (
            &self.peer_reference,
            self.config.reference_match,
            self.config.retired_action,
        )
    }

    /// The authority set used to judge reference manifests (separate set if
    /// configured, else the AK-endorsement anchors).
    fn reference_anchors(&self) -> &TrustAnchors {
        self.reference_authorities.as_ref().unwrap_or(&self.anchors)
    }

    /// Adopt a signed reference manifest if it verifies and its issuer chains to
    /// a trusted reference authority. Returns whether it was adopted. Idempotent
    /// — re-applying the same manifest is a no-op (design §10.2).
    pub fn apply_reference_manifest(&mut self, manifest: &ReferenceManifest) -> bool {
        if !manifest.verify_signature() {
            return false;
        }
        let id = manifest.content_id();
        if self.adopted_manifests.contains_key(&id) {
            return true; // already adopted — idempotent, no re-audit/re-gossip
        }
        let trusted = {
            let anchors = self.reference_anchors();
            manifest.issuer_chains_to_anchor(|k| anchors.trusts(k))
        };
        if !trusted {
            return false; // unsigned-by-anyone-we-trust → ignored
        }
        self.peer_reference.adopt_manifest(manifest);
        self.adopted_manifests.insert(id, manifest.clone());
        // Audit: append a hash-chained record committing to the adopted manifest.
        self.reference_audit.append(
            self.id,
            RecordType::ReferenceUpdate,
            id,
            self.tick,
            self.config.policy_revision,
        );
        true
    }

    /// Adopt a manifest locally and gossip it to peers, so every verifier that
    /// trusts the issuer converges on the same accepted set.
    pub fn broadcast_reference_manifest(&mut self, manifest: ReferenceManifest) {
        self.apply_reference_manifest(&manifest);
        self.broadcast(GossipMessage::ReferenceManifest(Box::new(manifest)));
    }

    /// Periodically advertise the set of manifest ids this node holds, so a peer
    /// that missed a gossiped manifest can pull it (anti-entropy, §10.2).
    fn advertise_references(&mut self, now: u64) {
        if self.config.reference_advertise_interval == 0 || self.adopted_manifests.is_empty() {
            return;
        }
        if now.saturating_sub(self.last_reference_advert) < self.config.reference_advertise_interval
        {
            return;
        }
        self.last_reference_advert = now;
        let ids: Vec<[u8; 32]> = self.adopted_manifests.keys().copied().collect();
        self.broadcast(GossipMessage::ReferenceDigest { ids });
    }

    /// On a peer's manifest-id advertisement, request any we are missing.
    fn on_reference_digest(&mut self, sender: NodeId, ids: Vec<[u8; 32]>) {
        for id in ids {
            if !self.adopted_manifests.contains_key(&id) {
                self.emit(sender, GossipMessage::ReferenceManifestRequest { id });
            }
        }
    }

    /// Serve a requested manifest we hold to the requester.
    fn on_reference_manifest_request(&mut self, sender: NodeId, id: [u8; 32]) {
        if let Some(m) = self.adopted_manifests.get(&id).cloned() {
            self.emit(sender, GossipMessage::ReferenceManifest(Box::new(m)));
        }
    }

    /// Whether this node has adopted the manifest with content id `id`.
    pub fn has_reference_manifest(&self, id: [u8; 32]) -> bool {
        self.adopted_manifests.contains_key(&id)
    }

    /// Length of the reference-adoption audit chain (testing/ops).
    pub fn reference_audit_len(&self) -> usize {
        self.reference_audit.len()
    }

    /// Whether the reference-adoption audit chain verifies intact.
    pub fn reference_audit_ok(&self) -> bool {
        self.reference_audit.verify_integrity().is_ok()
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

    /// Advertise this node's TLS certificate (DER) to the mesh (E2): it rides
    /// membership gossip so peers can pin it for mutual TLS.
    pub fn set_tls_cert(&mut self, cert: Vec<u8>) {
        self.membership.set_my_tls_cert(cert);
    }

    /// The pinnable peer roster — `(node, cert DER)` for every peer whose TLS
    /// certificate this node has learned via gossip. Feeds `mtls_client` /
    /// `serve_mtls`.
    pub fn tls_roster(&self) -> Vec<(NodeId, Vec<u8>)> {
        self.membership.tls_roster()
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

    /// Ingest this node's **own** IMA runtime measurement list (C1): preserve
    /// every measured file in the LtHash log — so runtime evidence is shipped,
    /// reconciled, and held across the mesh exactly like boot evidence — and
    /// appraise it against the runtime policy. Returns `(violations, ingested)`.
    /// (PCR 10 should be classed [`crate::reference::PcrClass::Runtime`]: its
    /// value grows monotonically; integrity comes from this log, not the value.)
    pub fn ingest_own_ima(
        &mut self,
        ima_ascii: &str,
    ) -> (Vec<crate::runtime::RuntimeViolation>, usize) {
        let (log, _skipped) = tpm_core::ima::ImaLog::parse_ascii(ima_ascii);
        for e in &log.entries {
            // A canonical per-entry element binding the template hash, path, and
            // file content hash — stable across nodes for reconciliation.
            let mut buf = Vec::new();
            buf.extend_from_slice(&e.template_hash);
            buf.extend_from_slice(e.path.as_bytes());
            buf.extend_from_slice(e.file_algo.as_bytes());
            buf.extend_from_slice(&e.file_hash);
            let digest = tpm_core::backend::hash_for_bank("sha256", &buf).unwrap_or_default();
            if digest.len() >= 32 {
                let mut element = [0u8; 32];
                element.copy_from_slice(&digest[..32]);
                self.append_event(element);
            }
        }
        let violations = self.runtime_policy.appraise(&log);
        (violations, log.entries.len())
    }

    /// Ingest this node's own firmware measured-boot log (B1): preserve every
    /// measured-boot event in the LtHash log — so firmware evidence is shipped,
    /// reconciled, and held across the mesh exactly like the IMA list and boot
    /// quote — parsing the raw TCG `binary_bios_measurements` (or the Citadel
    /// JSON form). Returns the number of events ingested. Pairs with
    /// [`Self::stage_event_log`], which ships the raw log in evidence.
    pub fn ingest_own_event_log(&mut self, event_log: &[u8]) -> anyhow::Result<usize> {
        let log = BootEventLog::from_bytes(event_log)?;
        let bank = self.config.pcr_bank.clone();
        for ev in &log.events {
            // A canonical per-event element binding the PCR, TCG event type, and
            // the measured digest for this bank — stable across nodes for
            // reconciliation (the digest is the PCR-bound part of the event).
            let mut buf = Vec::new();
            buf.extend_from_slice(&ev.pcr.to_le_bytes());
            buf.extend_from_slice(&ev.tcg_type().unwrap_or(0).to_le_bytes());
            if let Some(digest) = ev.measured_digest(&bank) {
                buf.extend_from_slice(digest);
            }
            let element = tpm_core::backend::hash_for_bank("sha256", &buf).unwrap_or_default();
            if element.len() >= 32 {
                let mut payload = [0u8; 32];
                payload.copy_from_slice(&element[..32]);
                self.append_event(payload);
            }
        }
        Ok(log.events.len())
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
        self.replicas
            .iter()
            .map(|(id, log)| (*id, log.root()))
            .collect()
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

    // -- signed quote-bound checkpoints (design §9-10) -------------------

    /// Build a signed, quote-bound checkpoint for one **sealed**, non-empty
    /// own-log window: quote with a nonce that binds the TPM to the window root,
    /// then sign the whole record with the mesh key. `None` if the window is
    /// unsealed, empty, or the quote fails.
    pub fn checkpoint_window(&self, window_id: u64) -> Option<Checkpoint> {
        let size = self.config.log_window_size;
        let lo = window_id.saturating_mul(size);
        let hi = lo.saturating_add(size);
        if self.own_log.max_sequence() + 1 < hi {
            return None; // not yet sealed
        }
        if self.own_log.records_in(lo, hi).is_empty() {
            return None; // empty window
        }
        let root = self.own_log.window_root(window_id);
        let nonce = checkpoint_nonce(self.config.boot_id, window_id, &root);
        let challenge = AttestationChallenge {
            challenger: self.id,
            subject: self.id,
            nonce,
            pcr_bank: self.config.pcr_bank.clone(),
            pcr_selection: self.config.pcr_selection.clone(),
            policy_revision: self.config.policy_revision,
            expires_at_tick: self.tick + 5,
        };
        let ev = self
            .attestor
            .produce(
                &challenge,
                self.config.policy_revision,
                None,
                None,
                self.tick,
            )
            .ok()?;
        Some(Checkpoint::sign(
            &self.keypair,
            self.id,
            self.config.boot_id,
            window_id,
            self.own_log.max_sequence(),
            root,
            ev.quote,
            self.tick,
        ))
    }

    /// Emit signed checkpoints for sealed own-log windows whose root we have not
    /// yet checkpointed (a forked rewrite changes the root and re-emits — which
    /// is exactly how peers catch equivocation).
    fn advertise_checkpoints(&mut self, _now: u64) {
        if !self.config.checkpoint_enabled || self.own_log.is_empty() {
            return;
        }
        let size = self.config.log_window_size;
        let max_seq = self.own_log.max_sequence();
        for window_id in self.own_log.windows() {
            let hi = window_id.saturating_mul(size).saturating_add(size);
            if max_seq + 1 < hi {
                continue; // not sealed
            }
            let root = self.own_log.window_root(window_id);
            let key = (self.config.boot_id, window_id);
            if self.emitted_checkpoints.get(&key) == Some(&root) {
                continue; // already checkpointed at this root
            }
            if let Some(cp) = self.checkpoint_window(window_id) {
                self.emitted_checkpoints.insert(key, root);
                self.broadcast(GossipMessage::LogCheckpoint(Box::new(cp)));
            }
        }
    }

    /// Verify and record a peer's signed checkpoint; a conflicting root for an
    /// already-checkpointed `(node, boot, window)` is attributable equivocation.
    fn on_checkpoint(&mut self, sender: NodeId, cp: Checkpoint) {
        // A node only checkpoints its own log.
        if cp.node_id != sender {
            return;
        }
        let Some(member) = self.membership.get(&sender) else {
            return;
        };
        // Mesh signature, quote↔root binding, and a genuine quote.
        if !cp.verify_signature(&member.public_key) || !cp.quote_binds_root() {
            return;
        }
        match self
            .attestor
            .backend()
            .verify_quote(&cp.quote, &cp.quote.ak_public, &cp.quote.nonce)
        {
            Ok(v) if v.signature_valid && v.nonce_matches => {}
            _ => return,
        }
        let key = (cp.node_id, cp.boot_id, cp.window_id);
        match self.checkpoints.get(&key) {
            Some(prev) if prev.lthash_root != cp.lthash_root => {
                // Two validly-signed, quote-bound roots for one sealed window —
                // non-repudiable proof the node forked its history.
                self.equivocations.push((prev.clone(), cp));
                self.membership.set_trust(&sender, TrustState::Suspicious);
            }
            Some(_) => {}
            None => {
                self.checkpoints.insert(key, cp);
            }
        }
    }

    /// Attributable equivocation proofs this node holds (pairs of conflicting
    /// signed checkpoints).
    pub fn equivocation_proofs(&self) -> &[(Checkpoint, Checkpoint)] {
        &self.equivocations
    }

    /// The signed checkpoint this node holds for a peer's sealed window, if any.
    pub fn checkpoint_for(
        &self,
        node: NodeId,
        boot_id: u64,
        window_id: u64,
    ) -> Option<&Checkpoint> {
        self.checkpoints.get(&(node, boot_id, window_id))
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
                    self.membership
                        .set_trust(&ad.node_id, TrustState::Suspicious);
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
            self.emit(
                sender,
                GossipMessage::LogRangeQuery {
                    boot_id: ad.boot_id,
                    lo,
                    hi,
                },
            );
        }
    }

    /// Continue the binary search for `sender`'s log: compare the advertiser's
    /// root over `[lo, hi)` to our replica's; descend only if they differ,
    /// pulling records once the range is small (design log-shipping §12).
    fn on_log_range_root(
        &mut self,
        sender: NodeId,
        boot_id: u64,
        lo: u64,
        hi: u64,
        remote_root: Vec<u8>,
    ) {
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
            self.emit(
                sender,
                GossipMessage::LogRangeQuery {
                    boot_id,
                    lo,
                    hi: mid,
                },
            );
            self.emit(
                sender,
                GossipMessage::LogRangeQuery {
                    boot_id,
                    lo: mid,
                    hi,
                },
            );
        }
    }

    /// Records this node has served to replicas (observability/tests).
    pub fn log_records_served(&self) -> usize {
        self.log_records_served
    }

    // -- durable evidence: erasure-coded sealed windows (design §12.4) ---

    /// The erasure scheme this node uses for durable window evidence.
    fn evidence_scheme(&self) -> Option<ErasureScheme> {
        ErasureScheme::new(
            self.config.evidence_data_shards,
            self.config.evidence_parity_shards,
        )
        .ok()
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
                self.held_fragments
                    .entry(record_id)
                    .or_default()
                    .insert(index, lf);
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
        let budget = self
            .config
            .evidence_migration_rate
            .saturating_sub(in_flight);
        if budget == 0 {
            return;
        }
        let to_start: Vec<(u64, u64, [u8; 32])> = self
            .shipped_windows
            .iter()
            .filter(|(_, w)| w.migrating.is_none() && (w.policy != target || w.scheme != scheme))
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
            let self_acked = self.scatter(
                record_id,
                boot_id,
                window_id,
                target,
                &new_holders,
                fragments,
            );
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
        self.held_fragments
            .entry(record_id)
            .or_default()
            .insert(index, lf);
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
        self.shipped_windows
            .get(&(boot_id, window_id))
            .map(|w| WindowPlacement {
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
        self.shipped_windows
            .get(&(boot_id, window_id))
            .map(|w| w.record_id)
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
        self.held_fragments
            .get(&record_id)
            .map(|m| m.len())
            .unwrap_or(0)
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
        self.advertise_checkpoints(now);
        self.ship_sealed_windows(now);
        self.migrate_windows(now);
        self.advertise_references(now);

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
                if !matches!(u.liveness, LivenessState::Alive)
                    && u.incarnation >= self.membership.my_incarnation()
                {
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
                // A witness's verdict: verify the verifier's signature (M1) —
                // a forged or tampered verdict can't sway the quorum — then
                // record it and re-aggregate the subject's trust.
                let ok = self
                    .membership
                    .get(&res.verifier)
                    .is_some_and(|m| res.verify_signature(&m.public_key));
                if ok {
                    self.record_report(res.subject, res.verifier, res.result);
                    self.aggregate_trust(res.subject);
                }
            }
            GossipMessage::LogDigest(ad) => self.on_log_digest(env.sender, ad, now),
            GossipMessage::LogRangeQuery { boot_id, lo, hi } => {
                // Answer with our own log's root over the queried range.
                if boot_id == self.config.boot_id {
                    let root = self.own_log.range_root(lo, hi);
                    self.emit(
                        env.sender,
                        GossipMessage::LogRangeRoot {
                            boot_id,
                            lo,
                            hi,
                            root,
                        },
                    );
                }
            }
            GossipMessage::LogRangeRoot {
                boot_id,
                lo,
                hi,
                root,
            } => {
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
            GossipMessage::ReferenceManifest(m) => {
                self.apply_reference_manifest(&m);
            }
            GossipMessage::ReferenceDigest { ids } => self.on_reference_digest(env.sender, ids),
            GossipMessage::ReferenceManifestRequest { id } => {
                self.on_reference_manifest_request(env.sender, id)
            }
            GossipMessage::LogCheckpoint(cp) => self.on_checkpoint(env.sender, *cp),
            GossipMessage::AppResult(r) => self.on_app_result(env.sender, *r),
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
        if let Ok(mut ev) = self.attestor.produce(
            &ch,
            self.config.policy_revision,
            None,
            self.endorsement.clone(),
            now,
        ) {
            // Ship the staged IMA runtime list so the verifier appraises what
            // ran after boot (C1).
            ev.ima_log = self.staged_ima.clone();
            // Ship the node's real firmware measured-boot log if staged from its
            // own /sys (B1), so the verifier replays exactly what its firmware
            // measured rather than the backend's synthesized log.
            if self.staged_event_log.is_some() {
                ev.event_log = self.staged_event_log.clone();
            }
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
        let (accepted, match_policy, retired_action) = self.appraisal_for(ev.subject);
        let mut result = self.attestor.verify(
            &ch,
            &ev,
            accepted,
            &self.anchors,
            self.id,
            now,
            match_policy,
            retired_action,
        );
        // C1: appraise the shipped IMA runtime list. A known-bad file that ran
        // escalates the subject locally (sticky, via `runtime_escalated`) *and*
        // fails the reported verdict, so the witness quorum carries the runtime
        // failure to every node — not just the witnesses that saw the evidence.
        if let Some(ima) = &ev.ima_log {
            let ascii = String::from_utf8_lossy(ima).into_owned();
            let violations = self.report_runtime(ev.subject, &ascii);
            if violations
                .iter()
                .any(|v| v.reason == crate::runtime::RuntimeReason::Denied)
            {
                result.result = Verdict::Fail;
                if !result.reason_codes.contains(&ReasonCode::ReferenceDenied) {
                    result.reason_codes.push(ReasonCode::ReferenceDenied);
                }
            }
        }
        let verdict = result.result;
        // Our own direct observation — provisional until (and unless) the
        // assigned-witness quorum decides otherwise in `aggregate_trust`.
        self.membership
            .set_trust(&ev.subject, verdict_to_trust(verdict));
        self.record_report(ev.subject, self.id, verdict);
        self.aggregate_trust(ev.subject);
        // Gossip the signed verdict so every node aggregates the same
        // witness quorum (design §9.1, §11.4). Signed by this verifier so it is
        // verifiable detached from the envelope (M1 / control-plane agreement).
        self.broadcast(GossipMessage::AttestResult(result.signed(&self.keypair)));
    }

    // -- witness duties + trust aggregation (design §10, §11) -----------

    /// The full set of node ids this node knows (its witness roster).
    /// The witness roster: all known members **except observers** (M0) — so
    /// observer/control-plane nodes are never assigned as witnesses fleet-wide.
    fn roster(&self) -> Vec<NodeId> {
        self.membership
            .iter()
            .filter(|m| !m.observer)
            .map(|m| m.node_id)
            .collect()
    }

    /// The node ids assigned to witness `subject` (observers excluded). Exposed
    /// for tests / the control plane to recompute agreement.
    pub fn witness_ids_for(&self, subject: NodeId) -> Vec<NodeId> {
        self.witnesses_for(subject).witnesses
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
        // Observers cast no verdicts (M0); they only ingest peers' gossiped ones.
        if self.config.observer || self.config.witness_count == 0 {
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
        // Likewise an app-escalated node stays distrusted until remediation —
        // a clean platform quote must not silently clear an app failure (§5.3).
        if self.app_escalated.contains(&subject) {
            self.membership.set_trust(&subject, TrustState::Suspicious);
            return;
        }
        // A runtime (IMA) escalation — a known-bad file executed — is likewise
        // sticky: the boot quote can be pristine while runtime integrity failed.
        if self.runtime_escalated.contains(&subject) {
            self.membership.set_trust(&subject, TrustState::Suspicious);
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
        let fails = relevant
            .iter()
            .filter(|v| matches!(v, Verdict::Fail))
            .count();
        let passes = relevant
            .iter()
            .filter(|v| matches!(v, Verdict::Pass))
            .count();
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
        let evidence = self.attestor.produce(
            &ach,
            self.config.policy_revision,
            Some(agent_version.to_string()),
            self.endorsement.clone(),
            self.tick,
        )?;
        // Present our TLS cert (if advertised) in the signed claim, so admitting
        // nodes learn it on the bootstrap channel before mTLS comes up (E2).
        let tls_cert = self
            .membership
            .get(&self.id)
            .and_then(|m| m.tls_cert.clone());
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
            tls_cert,
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
        EnrollmentVote::sign(
            &self.keypair,
            self.id,
            claim.candidate,
            verdict,
            reason,
            tick,
        )
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
        let existing: Vec<[u8; 32]> = self
            .membership
            .iter()
            .map(|m| m.public_key.fingerprint())
            .collect();
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
        let (accepted, match_policy, retired_action) = self.appraisal_for(claim.candidate);
        let result = self.attestor.verify(
            &ach,
            &claim.evidence,
            accepted,
            &self.anchors,
            self.id,
            tick,
            match_policy,
            retired_action,
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
        tls_cert: Option<Vec<u8>>,
    ) {
        self.membership.learn(node_id, key, role, tick);
        if let Some(cert) = tls_cert {
            self.membership.learn_cert(&node_id, cert);
        }
        self.membership
            .set_trust(&node_id, TrustState::Probationary);
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
        QuarantineProposal::create(
            &self.keypair,
            self.id,
            subject,
            reasons,
            scope,
            tick + 10,
            tick,
        )
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
            self.membership
                .set_trust(&subject, TrustState::Probationary);
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
        let (accepted, match_policy, retired_action) = self.appraisal_for(claim.candidate);
        self.attestor
            .verify(
                &ach,
                &claim.evidence,
                accepted,
                &self.anchors,
                self.id,
                tick,
                match_policy,
                retired_action,
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
