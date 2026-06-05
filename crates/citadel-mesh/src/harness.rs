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

use crate::attest::Attestor;
use crate::crypto::MeshKeypair;
use crate::id::{Epoch, MeshId, NodeId};
use crate::membership::Membership;
use crate::node::{Node, NodeConfig, WitnessSummary};
use crate::state::{LivenessState, TrustState};

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
}

impl Mesh {
    pub fn new(mesh_id: impl Into<String>) -> Self {
        Mesh {
            mesh_id: MeshId::new(mesh_id),
            nodes: Vec::new(),
            index: HashMap::new(),
            dead: HashSet::new(),
            settle_cap: 100_000,
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
        let keypair = MeshKeypair::from_seed([seed; 32]);
        let pubkey = keypair.public();
        let id = NodeId::derive(&self.mesh_id, Epoch(1), &pubkey.fingerprint(), &[seed]);
        let membership = Membership::new(id, pubkey, role, 0);
        let attestor = Attestor::new(backend).expect("attestor");
        let node = Node::new(self.mesh_id.clone(), id, keypair, membership, attestor, config);
        self.index.insert(id, self.nodes.len());
        self.nodes.push(node);
        id
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
