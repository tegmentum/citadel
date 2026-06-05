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

use std::collections::HashMap;

use crate::attest::{Attestor, ReferenceMeasurements};
use crate::crypto::MeshKeypair;
use crate::enrollment::{
    self, AdmissionReason, AdmissionVerdict, EnrollmentChallenge, EnrollmentClaim, EnrollmentVote,
};
use crate::id::{Epoch, MeshId, NodeId};
use crate::membership::Membership;
use crate::state::{LivenessState, TrustState};
use crate::types::{AttestationChallenge, GossipEnvelope, GossipMessage, Verdict};
use crate::witness;

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
    /// The golden measured state this node expects of peers it verifies
    /// (the Reference Value Provider's output; design §8.1, §14.2). Empty
    /// until installed from policy — verification is then Inconclusive.
    peer_reference: ReferenceMeasurements,
    /// Latest attestation verdict per `subject → verifier` heard on the mesh
    /// (own + gossiped). Aggregated by assigned-witness quorum into trust.
    witness_reports: HashMap<NodeId, HashMap<NodeId, Verdict>>,
    /// Last tick this node (as a witness) challenged each subject.
    last_challenge: HashMap<NodeId, u64>,
    /// Tick at which each subject was admitted to probation — used to gate
    /// promotion to `Trusted` after the probation window.
    probation_start: HashMap<NodeId, u64>,
    outbox: Vec<Addressed>,
}

impl Node {
    pub fn new(
        mesh_id: MeshId,
        id: NodeId,
        keypair: MeshKeypair,
        membership: Membership,
        attestor: Attestor,
        config: NodeConfig,
    ) -> Self {
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
            peer_reference: ReferenceMeasurements::default(),
            witness_reports: HashMap::new(),
            last_challenge: HashMap::new(),
            probation_start: HashMap::new(),
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
    /// (from signed policy / a known-good node).
    pub fn set_peer_reference(&mut self, reference: ReferenceMeasurements) {
        self.peer_reference = reference;
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
            GossipMessage::AttestEvidence(ev) => self.on_evidence(ev, now),
            GossipMessage::AttestResult(res) => {
                // A witness's verdict: record it and re-aggregate the
                // subject's trust from its assigned witnesses.
                self.record_report(res.subject, res.verifier, res.result);
                self.aggregate_trust(res.subject);
            }
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
        if let Ok(ev) = self.attestor.produce(&ch, self.config.policy_revision, None, now) {
            self.emit(ch.challenger, GossipMessage::AttestEvidence(ev));
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
            .verify(&ch, &ev, &self.peer_reference, self.id, now);
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
                .produce(&ach, self.config.policy_revision, Some(agent_version.to_string()), self.tick)?;
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
            .verify(&ach, &claim.evidence, &self.peer_reference, self.id, tick);
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
