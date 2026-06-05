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

use crate::attest::{Attestor, ReferenceMeasurements};
use crate::crypto::MeshKeypair;
use crate::id::{MeshId, NodeId};
use crate::membership::Membership;
use crate::state::{LivenessState, TrustState};
use crate::types::{
    AttestationChallenge, GossipEnvelope, GossipMessage, Verdict,
};

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
        }
    }
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
            probe_cursor: 0,
            pending: None,
            owed: Vec::new(),
            issued_challenges: Vec::new(),
            peer_reference: ReferenceMeasurements::default(),
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
            GossipMessage::AttestResult(_res) => {
                // Phase 0: witness-result aggregation is Phase 3; ignore.
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
        let trust = match result.result {
            Verdict::Pass => TrustState::Trusted,
            Verdict::Warn => TrustState::Degraded,
            Verdict::Fail => TrustState::Suspicious,
            Verdict::Inconclusive => TrustState::Unknown,
        };
        self.membership.set_trust(&ev.subject, trust);
        // Gossip the signed result to the subject's peers (Phase 3 will
        // aggregate these into witness quorum; Phase 0 just disseminates).
        self.broadcast(GossipMessage::AttestResult(result));
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
