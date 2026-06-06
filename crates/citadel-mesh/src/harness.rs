//! An in-process mesh of [`Node`]s for deterministic testing.
//!
//! The harness owns every node and a single message queue. One [`step`]
//! does:
//!
//! 1. **tick** every live node (run failure detectors, start probes);
//! 2. **settle** — deliver every queued message to its (live) recipient and
//!    drain the replies it produces, repeating until the queue is empty.
//!
//! Because acks settle within the same step, a *live* target is confirmed
//! immediately, while a *killed* target (one [`kill`]ed out of the mesh)
//! produces no ack and is driven `Alive → Suspect → Faulty` by the protocol.
//! No sockets, no clocks, no threads — fully reproducible.
//!
//! [`step`]: Mesh::step
//! [`kill`]: Mesh::kill

use std::collections::{HashMap, HashSet};

use tpm_core::backend::{MockBackend, TpmBackend};

use crate::attest::{Attestor, ReferenceMeasurements, TrustAnchors};
use crate::crypto::{MeshKeypair, MeshPublicKey};
use crate::enrollment::{self, AdmissionOutcome, EnrollmentChallenge};
use crate::types::Endorsement;
use crate::id::{Epoch, MeshId, NodeId};
use crate::membership::Membership;
use crate::node::{Node, NodeConfig, WitnessSummary};
use crate::quarantine::{self, QuarantineDecision, QuarantineScope};
use crate::reference::{PcrClass, Validity};
use crate::state::{LivenessState, TrustState};
use crate::witness;

/// Per-node snapshot for the "dashboard" view (design §17.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateRow {
    pub node_id: NodeId,
    pub liveness: LivenessState,
    pub trust: TrustState,
}

/// Aggregate counts from one observer's point of view (design §17.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FleetView {
    pub total: usize,
    pub alive: usize,
    pub suspect: usize,
    pub faulty: usize,
    pub trusted: usize,
    pub suspicious: usize,
}

/// An in-process mesh.
pub struct Mesh {
    mesh_id: MeshId,
    nodes: Vec<Node>,
    index: HashMap<NodeId, usize>,
    dead: HashSet<NodeId>,
    /// Safety bound on the per-step settle loop.
    settle_cap: usize,
    /// Wall-clock-free logical tick, advanced once per [`Mesh::step`].
    tick: u64,
    /// The golden reference adopted at wiring (for enrolling new nodes).
    golden: ReferenceMeasurements,
    /// Config template (the first node's) used for enrolled candidates.
    template_config: Option<NodeConfig>,
}

impl Mesh {
    pub fn new(mesh_id: impl Into<String>) -> Self {
        Mesh {
            mesh_id: MeshId::new(mesh_id),
            nodes: Vec::new(),
            index: HashMap::new(),
            dead: HashSet::new(),
            settle_cap: 100_000,
            tick: 0,
            golden: ReferenceMeasurements::default(),
            template_config: None,
        }
    }

    /// Add a node with a deterministic keypair (seeded by `seed`). Returns
    /// its derived [`NodeId`]. Call [`Self::wire_full_membership`] after all
    /// nodes are added so each learns the others (Phase 0 seed = fully
    /// connected).
    pub fn add_node(&mut self, seed: u8, role: &str, config: NodeConfig) -> NodeId {
        self.add_node_with_backend(seed, role, config, Box::new(MockBackend::new()))
    }

    /// Add a node backed by a specific TPM backend (e.g. a real vTPM for the
    /// Phase 1 hardware acceptance test). Same seam as [`Self::add_node`].
    pub fn add_node_with_backend(
        &mut self,
        seed: u8,
        role: &str,
        config: NodeConfig,
        backend: Box<dyn TpmBackend>,
    ) -> NodeId {
        if self.template_config.is_none() {
            self.template_config = Some(config.clone());
        }
        let node = self.make_node(seed, role, config, backend);
        let id = node.id();
        self.index.insert(id, self.nodes.len());
        self.nodes.push(node);
        id
    }

    /// Construct a node without inserting it into the mesh (used for both
    /// `add_node` and enrolling a candidate).
    fn make_node(
        &self,
        seed: u8,
        role: &str,
        config: NodeConfig,
        backend: Box<dyn TpmBackend>,
    ) -> Node {
        let keypair = MeshKeypair::from_seed([seed; 32]);
        let pubkey = keypair.public();
        let id = NodeId::derive(&self.mesh_id, Epoch(config.mesh_epoch), &pubkey.fingerprint(), &[seed]);
        let membership = Membership::new(id, pubkey, role, 0);
        let attestor = Attestor::new(backend).expect("attestor");
        Node::new(self.mesh_id.clone(), id, keypair, membership, attestor, config)
    }

    /// Make every node learn every other node (seed membership) and adopt a
    /// uniform golden reference captured from the first (known-good) node, so
    /// peer attestation has a policy baseline to match against.
    pub fn wire_full_membership(&mut self) {
        let roster: Vec<(NodeId, crate::crypto::MeshPublicKey)> = self
            .nodes
            .iter()
            .map(|n| (n.id(), n.membership().get(&n.id()).unwrap().public_key))
            .collect();
        let reference = self
            .nodes
            .first()
            .and_then(|n| n.current_reference().ok())
            .unwrap_or_default();
        self.golden = reference.clone();
        for node in &mut self.nodes {
            for (id, key) in &roster {
                if *id != node.id() {
                    node.learn_peer(*id, *key, "worker", 0);
                }
            }
            node.set_peer_reference(reference.clone());
        }
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[self.index[&id]]
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        let i = self.index[&id];
        &mut self.nodes[i]
    }

    /// Remove a node from the mesh (it stops ticking and stops receiving):
    /// a crash/partition for the failure detector to discover.
    pub fn kill(&mut self, id: NodeId) {
        self.dead.insert(id);
    }

    /// Bring a killed node back (it resumes ticking/receiving). It will
    /// refute any lingering suspicion by bumping its incarnation.
    pub fn revive(&mut self, id: NodeId) {
        self.dead.remove(&id);
    }

    /// Advance the whole mesh one step.
    pub fn step(&mut self) {
        self.tick += 1;
        // 1) tick every live node and collect its outbound messages.
        let mut queue: Vec<crate::node::Addressed> = Vec::new();
        for node in &mut self.nodes {
            if self.dead.contains(&node.id()) {
                continue;
            }
            node.tick();
            queue.append(&mut node.take_outbox());
        }
        // 2) settle: deliver, drain replies, repeat until quiescent.
        let mut delivered = 0usize;
        while let Some(msg) = queue.pop() {
            delivered += 1;
            assert!(delivered < self.settle_cap, "settle loop did not converge");
            if self.dead.contains(&msg.to) {
                continue;
            }
            let Some(&i) = self.index.get(&msg.to) else {
                continue;
            };
            self.nodes[i].deliver(msg.envelope);
            queue.append(&mut self.nodes[i].take_outbox());
        }
    }

    /// Run `n` steps.
    pub fn run(&mut self, n: usize) {
        for _ in 0..n {
            self.step();
        }
    }

    // -- observation ----------------------------------------------------

    /// The full membership view as seen by `observer`.
    pub fn rows_as_seen_by(&self, observer: NodeId) -> Vec<NodeStateRow> {
        self.node(observer)
            .membership()
            .iter()
            .map(|m| NodeStateRow {
                node_id: m.node_id,
                liveness: m.liveness,
                trust: m.trust,
            })
            .collect()
    }

    /// How `observer` classifies `subject`'s liveness.
    pub fn liveness_of(&self, observer: NodeId, subject: NodeId) -> Option<LivenessState> {
        self.node(observer).membership().get(&subject).map(|m| m.liveness)
    }

    /// How `observer` classifies `subject`'s trust.
    pub fn trust_of(&self, observer: NodeId, subject: NodeId) -> Option<TrustState> {
        self.node(observer).membership().get(&subject).map(|m| m.trust)
    }

    /// The witnesses `observer` assigns to `subject` this epoch.
    pub fn assigned_witnesses(&self, observer: NodeId, subject: NodeId) -> Vec<NodeId> {
        self.node(observer).assigned_witnesses(subject)
    }

    /// How `subject`'s assigned witnesses currently vote, from `observer`'s
    /// collected reports (the dashboard "agreement" view, design §17.4).
    pub fn witness_summary(&self, observer: NodeId, subject: NodeId) -> WitnessSummary {
        self.node(observer).witness_summary(subject)
    }

    // -- enrollment (design §7) -----------------------------------------

    /// Whether `witness` is eligible to vote on admissions — i.e. an
    /// established, trusted member (not probationary/unknown), as judged by
    /// the founding authority's view. A node on probation cannot vote.
    pub fn is_eligible_voter(&self, witness: NodeId) -> bool {
        let authority = self.nodes[0].id();
        // A node quarantined at/above RestrictMeshVoting loses its vote.
        if self
            .node(authority)
            .quarantine_of(witness)
            .is_some_and(|s| s.restricts_voting())
        {
            return false;
        }
        witness == authority
            || matches!(
                self.trust_of(authority, witness),
                Some(TrustState::Trusted) | Some(TrustState::Degraded)
            )
    }

    /// The quarantine scope on `subject` as the founding authority sees it.
    pub fn quarantine_of(&self, subject: NodeId) -> Option<QuarantineScope> {
        self.node(self.nodes[0].id()).quarantine_of(subject)
    }

    // -- endorsement (design §8.1, AK trust roots) ----------------------

    /// Make every node require endorsement from `anchors` (so unendorsed AKs
    /// are flagged `AK_UNTRUSTED`).
    pub fn set_anchors_all(&mut self, anchors: TrustAnchors) {
        for n in &mut self.nodes {
            n.set_trust_anchors(anchors.clone());
        }
    }

    /// Retarget durable-evidence placement across every node: the policy for
    /// new windows (`offbox`), the erasure `parity` paired with it, and the
    /// per-node migration concurrency. Models an operator flipping the
    /// placement policy (and bumping redundancy) on a live mesh.
    pub fn set_evidence_placement_all(&mut self, offbox: bool, parity: usize, migration_rate: usize) {
        for n in &mut self.nodes {
            n.set_evidence_placement(offbox, parity, migration_rate);
        }
    }

    /// As `endorser`, endorse a node's AK and attach the endorsement to it, so
    /// anchored verifiers accept its quotes.
    pub fn endorse(&mut self, node_id: NodeId, endorser: &MeshKeypair) {
        let ak = self.node(node_id).ak_public();
        let endorsement = Endorsement::issue(endorser, node_id, ak);
        self.node_mut(node_id).set_endorsement(endorsement);
    }

    /// Propose and vote on quarantining `subject` at `scope`. The subject's
    /// witnesses vote (approving if they see it suspicious/isolated); the
    /// action is enacted only on the scope's quorum — plus `operator_approved`
    /// for the most severe scopes (design §13.4). On enactment every member
    /// applies the scope.
    pub fn propose_quarantine(
        &mut self,
        proposer: NodeId,
        subject: NodeId,
        scope: QuarantineScope,
        operator_approved: bool,
    ) -> QuarantineDecision {
        let tick = self.tick;
        let cfg = self.template_config.clone().unwrap_or_default();
        let roster: Vec<NodeId> = self.nodes.iter().map(|n| n.id()).collect();
        let ws = witness::assign(subject, &roster, Epoch(cfg.mesh_epoch), cfg.witness_count.max(1));

        let proposal = self.node(proposer).propose_quarantine(subject, scope, tick);
        let mut votes = Vec::new();
        let mut eligible = HashSet::new();
        for w in &ws.witnesses {
            votes.push(self.node(*w).vote_on_quarantine(&proposal, tick));
            if self.is_eligible_voter(*w) {
                eligible.insert(*w);
            }
        }
        let decision = quarantine::decide_quarantine(
            &proposal,
            &votes,
            &eligible,
            cfg.witness_count.max(1),
            operator_approved,
        );
        if decision.enacted {
            for n in &mut self.nodes {
                n.apply_quarantine(subject, scope, tick);
            }
        }
        decision
    }

    // -- measured-state transitions (design `measured-state-transitions.md`) --

    /// Simulate a measured-state change on a node — a kernel/firmware upgrade
    /// reboots into a new measured state by extending a PCR. Whether this is
    /// later treated as an authorized upgrade or as tamper depends only on
    /// whether the new digest is authorized via [`Self::authorize_reference_all`].
    pub fn measured_state_change(&self, node: NodeId, bank: &str, index: u32, data: &[u8]) {
        self.node(node)
            .attestor()
            .backend()
            .pcr_extend(bank, index, data)
            .expect("pcr extend");
    }

    /// A node's current digest for a PCR index — what an RVP would measure from
    /// the approved build in order to authorize it.
    pub fn pcr_digest(&self, node: NodeId, bank: &str, index: u32) -> Vec<u8> {
        self.node(node)
            .attestor()
            .backend()
            .pcr_read(bank, &[index])
            .expect("pcr read")
            .into_iter()
            .next()
            .expect("one value")
            .digest
    }

    /// Authorize a new accepted measured state across every verifier (a signed
    /// reference update in production; applied directly here for Phase 1).
    pub fn authorize_reference_all(&mut self, index: u32, digest: Vec<u8>, validity: Validity) {
        for n in &mut self.nodes {
            n.accept_reference(index, digest.clone(), validity.clone());
        }
    }

    /// Set the appraisal class for a PCR index across every verifier (§10.1).
    pub fn set_pcr_class_all(&mut self, index: u32, class: PcrClass) {
        for n in &mut self.nodes {
            n.set_pcr_class(index, class);
        }
    }

    /// Simulate remediation (a clean reimage): replace `subject`'s backend so
    /// it once again attests to the golden state.
    pub fn remediate(&mut self, subject: NodeId) {
        self.node_mut(subject)
            .replace_backend(Box::new(MockBackend::new()))
            .expect("fresh backend");
    }

    /// An isolated node requests to rejoin: it re-attests, its witnesses vote,
    /// and on quorum the quarantine is lifted — returning it to **probation**,
    /// not straight to trusted (design §13.5). Returns whether it rejoined.
    pub fn rejoin(&mut self, subject: NodeId) -> bool {
        let tick = self.tick;
        let cfg = self.template_config.clone().unwrap_or_default();
        let roster: Vec<NodeId> = self.nodes.iter().map(|n| n.id()).collect();
        let ws = witness::assign(subject, &roster, Epoch(cfg.mesh_epoch), cfg.witness_count.max(1));

        let challenge = EnrollmentChallenge {
            mesh_id: self.mesh_id.clone(),
            candidate: subject,
            nonce: enroll_nonce(subject, tick),
            pcr_bank: cfg.pcr_bank.clone(),
            pcr_selection: cfg.pcr_selection.clone(),
            policy_revision: cfg.policy_revision,
            admission_witnesses: ws.witnesses.clone(),
            quorum_threshold: ws.quorum_threshold,
        };
        let claim = match self.node(subject).make_enrollment_claim(&challenge, "worker", "v2") {
            Ok(c) => c,
            Err(_) => return false,
        };

        let mut approvals = 0usize;
        for w in &ws.witnesses {
            if self.is_eligible_voter(*w) && self.node(*w).verify_rejoin(&claim, &challenge, tick) {
                approvals += 1;
            }
        }
        let lifted = approvals >= ws.quorum_threshold;
        if lifted {
            for n in &mut self.nodes {
                n.lift_quarantine(subject, tick);
            }
        }
        lifted
    }

    /// Attempt to enroll a new node (healthy candidate). See
    /// [`Self::enroll_inner`].
    pub fn enroll(&mut self, seed: u8, role: &str) -> (AdmissionOutcome, NodeId) {
        self.enroll_inner(seed, role, false)
    }

    /// Attempt to enroll a candidate whose measured state diverges from the
    /// golden (a tampered/unauthorized image) — admission should be refused.
    pub fn enroll_tampered(&mut self, seed: u8, role: &str) -> (AdmissionOutcome, NodeId) {
        self.enroll_inner(seed, role, true)
    }

    fn enroll_inner(&mut self, seed: u8, role: &str, tamper: bool) -> (AdmissionOutcome, NodeId) {
        let tick = self.tick;
        let cfg = self.template_config.clone().unwrap_or_default();

        // Build the candidate (not yet in the mesh) and give it the golden
        // reference so it could later witness others.
        let mut candidate = self.make_node(seed, role, cfg.clone(), Box::new(MockBackend::new()));
        candidate.set_peer_reference(self.golden.clone());
        if tamper {
            candidate
                .attestor()
                .backend()
                .pcr_extend("sha256", 0, &[0xAA; 32])
                .unwrap();
        }
        let candidate_id = candidate.id();
        let candidate_key = candidate
            .membership()
            .get(&candidate_id)
            .expect("self in membership")
            .public_key;

        // Assign admission witnesses from the existing roster (HRW).
        let roster: Vec<NodeId> = self.nodes.iter().map(|n| n.id()).collect();
        let ws = witness::assign(
            candidate_id,
            &roster,
            Epoch(cfg.mesh_epoch),
            cfg.witness_count.max(1),
        );

        let challenge = EnrollmentChallenge {
            mesh_id: self.mesh_id.clone(),
            candidate: candidate_id,
            nonce: enroll_nonce(candidate_id, tick),
            pcr_bank: cfg.pcr_bank.clone(),
            pcr_selection: cfg.pcr_selection.clone(),
            policy_revision: cfg.policy_revision,
            admission_witnesses: ws.witnesses.clone(),
            quorum_threshold: ws.quorum_threshold,
        };
        let claim = candidate
            .make_enrollment_claim(&challenge, role, "v1")
            .expect("candidate produces a claim");

        // Collect each witness's signed vote; only eligible (trusted)
        // witnesses count toward the quorum.
        let mut votes = Vec::new();
        let mut eligible = HashSet::new();
        for w in &ws.witnesses {
            votes.push(self.node(*w).vote_on_enrollment(&claim, &challenge, tick));
            if self.is_eligible_voter(*w) {
                eligible.insert(*w);
            }
        }
        let outcome = enrollment::decide_admission(&votes, &eligible, ws.quorum_threshold);

        if outcome.admitted {
            let roster_keys: Vec<(NodeId, MeshPublicKey)> = self
                .nodes
                .iter()
                .map(|n| (n.id(), n.membership().get(&n.id()).unwrap().public_key))
                .collect();
            // Existing members admit the candidate as probationary.
            for n in &mut self.nodes {
                n.admit_probationary(candidate_id, candidate_key, role, tick);
            }
            // The candidate learns the existing members.
            for (id, key) in &roster_keys {
                candidate.learn_peer(*id, *key, role, tick);
            }
            self.index.insert(candidate_id, self.nodes.len());
            self.nodes.push(candidate);
        }
        (outcome, candidate_id)
    }

    /// Aggregate fleet view from `observer`'s membership (design §17.1).
    pub fn fleet_view(&self, observer: NodeId) -> FleetView {
        let mut v = FleetView::default();
        for m in self.node(observer).membership().iter() {
            v.total += 1;
            match m.liveness {
                LivenessState::Alive => v.alive += 1,
                LivenessState::Suspect => v.suspect += 1,
                LivenessState::Faulty => v.faulty += 1,
                _ => {}
            }
            match m.trust {
                TrustState::Trusted => v.trusted += 1,
                TrustState::Suspicious => v.suspicious += 1,
                _ => {}
            }
        }
        v
    }
}

/// Deterministic enrollment nonce from the candidate id and the mesh tick.
fn enroll_nonce(candidate: NodeId, tick: u64) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"citadel-enroll-nonce\x00");
    h.update(&candidate.0);
    h.update(&tick.to_be_bytes());
    h.finalize().as_bytes()[..16].to_vec()
}
