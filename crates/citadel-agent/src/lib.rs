//! # citadel-agent
//!
//! Runs a [`citadel_mesh`] node as a real, networked process. The mesh
//! protocol core is synchronous and transport-agnostic; this crate wraps one
//! [`Node`] in an async **actor** (a single owning task fed by a command
//! channel) and dispatches its outbound gossip through a pluggable
//! [`Transport`]:
//!
//! * [`ChannelSwitchboard`] — in-process delivery between actors, for
//!   deterministic multi-node tests without sockets;
//! * [`HttpTransport`] — `POST /v1/gossip` to peers, for deployment.
//!
//! The node logic is untouched: the actor just calls `tick()`/`deliver()` and
//! drains `take_outbox()` to the transport.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use citadel_mesh::attest::{Attestor, TrustAnchors};
use citadel_mesh::crypto::MeshKeypair;
use citadel_mesh::id::{Epoch, MeshId};
use citadel_mesh::membership::Membership;
use citadel_mesh::node::{Node, NodeConfig};
use citadel_mesh::reference::ReferenceManifest;
use citadel_mesh::types::GossipEnvelope;
use citadel_mesh::NodeId;
use tpm_core::backend::{MockBackend, TpmBackend};

pub mod http;

/// Fire-and-forget delivery of a signed envelope to a peer, addressed by id.
/// Implementations must be cheap/non-blocking (the actor calls this inline).
pub trait Transport: Send + Sync + 'static {
    fn dispatch(&self, to: NodeId, envelope: GossipEnvelope);
}

/// Commands processed by the node actor.
enum Cmd {
    Tick,
    Deliver(Box<GossipEnvelope>),
    Status(oneshot::Sender<Vec<MemberRow>>),
    AppendEvent([u8; 32]),
    LogState(oneshot::Sender<LogState>),
    SetReferenceAuthorities(Box<TrustAnchors>),
    ApplyReferenceManifest(Box<ReferenceManifest>),
    BroadcastReferenceManifest(Box<ReferenceManifest>),
    HasReferenceManifest([u8; 32], oneshot::Sender<bool>),
    TrustOf(NodeId, oneshot::Sender<Option<String>>),
}

/// This node's log-shipping view: the root of its own measurement log and of
/// each peer log it replicates (hex).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LogState {
    pub own_root: String,
    pub replicas: std::collections::HashMap<String, String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A row of the agent's membership view (for `GET /v1/mesh/status`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MemberRow {
    pub node_id: String,
    pub liveness: String,
    pub trust: String,
}

/// A cloneable handle to a running node actor.
#[derive(Clone)]
pub struct AgentHandle {
    cmd: mpsc::Sender<Cmd>,
    id: NodeId,
    aborts: Arc<Vec<AbortHandle>>,
}

impl AgentHandle {
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Stop the node: abort its actor and ticker tasks. It then neither
    /// gossips nor responds — a crash/partition for peers to detect.
    pub fn shutdown(&self) {
        for a in self.aborts.iter() {
            a.abort();
        }
    }

    /// Deliver an inbound envelope to the node.
    pub async fn deliver(&self, envelope: GossipEnvelope) {
        let _ = self.cmd.send(Cmd::Deliver(Box::new(envelope))).await;
    }

    /// Snapshot the node's membership view.
    pub async fn status(&self) -> Vec<MemberRow> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Status(tx)).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Append a measurement event to this node's own log.
    pub async fn append_event(&self, payload_hash: [u8; 32]) {
        let _ = self.cmd.send(Cmd::AppendEvent(payload_hash)).await;
    }

    /// Snapshot this node's own log root and the replica roots it holds.
    pub async fn log_state(&self) -> LogState {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::LogState(tx)).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            LogState::default()
        }
    }

    /// Install the authorities this node trusts to sign reference manifests.
    pub async fn set_reference_authorities(&self, authorities: TrustAnchors) {
        let _ = self.cmd.send(Cmd::SetReferenceAuthorities(Box::new(authorities))).await;
    }

    /// Adopt a signed reference manifest locally (no gossip) — for seeding one
    /// node so anti-entropy spreads it to the rest.
    pub async fn apply_reference_manifest(&self, manifest: ReferenceManifest) {
        let _ = self.cmd.send(Cmd::ApplyReferenceManifest(Box::new(manifest))).await;
    }

    /// Adopt a signed reference manifest and gossip it to peers.
    pub async fn broadcast_reference_manifest(&self, manifest: ReferenceManifest) {
        let _ = self.cmd.send(Cmd::BroadcastReferenceManifest(Box::new(manifest))).await;
    }

    /// Whether this node has adopted the manifest with content id `id`.
    pub async fn has_reference_manifest(&self, id: [u8; 32]) -> bool {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::HasReferenceManifest(id, tx)).await.is_ok() {
            rx.await.unwrap_or(false)
        } else {
            false
        }
    }

    /// This node's trust classification of `subject`, if known.
    pub async fn trust_of(&self, subject: NodeId) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::TrustOf(subject, tx)).await.is_ok() {
            rx.await.unwrap_or(None)
        } else {
            None
        }
    }

    fn sender(&self) -> mpsc::Sender<Cmd> {
        self.cmd.clone()
    }
}

/// Spawn a node actor: one task owns `node` and processes ticks, inbound
/// deliveries, and status queries; a second task fires a tick every
/// `tick_interval`. Outbound gossip is dispatched through `transport`.
pub fn spawn_node(
    node: Node,
    transport: Arc<dyn Transport>,
    tick_interval: Duration,
) -> AgentHandle {
    let id = node.id();
    let (tx, mut rx) = mpsc::channel::<Cmd>(1024);

    // Ticker — first tick after one interval, giving callers time to wire
    // peers/transport before any gossip is emitted.
    let ticker = tx.clone();
    let ticker_task = tokio::spawn(async move {
        let start = tokio::time::Instant::now() + tick_interval;
        let mut iv = tokio::time::interval_at(start, tick_interval);
        loop {
            iv.tick().await;
            if ticker.send(Cmd::Tick).await.is_err() {
                break;
            }
        }
    });

    // Actor.
    let actor_task = tokio::spawn(async move {
        let mut node = node;
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Cmd::Tick => {
                    node.tick();
                    drain_outbox(&mut node, &transport);
                }
                Cmd::Deliver(env) => {
                    node.deliver(*env);
                    drain_outbox(&mut node, &transport);
                }
                Cmd::Status(reply) => {
                    let _ = reply.send(snapshot(&node));
                }
                Cmd::AppendEvent(payload) => {
                    node.append_event(payload);
                    drain_outbox(&mut node, &transport);
                }
                Cmd::LogState(reply) => {
                    let _ = reply.send(log_state(&node));
                }
                Cmd::SetReferenceAuthorities(anchors) => {
                    node.set_reference_authorities(*anchors);
                }
                Cmd::ApplyReferenceManifest(m) => {
                    node.apply_reference_manifest(&m);
                }
                Cmd::BroadcastReferenceManifest(m) => {
                    node.broadcast_reference_manifest(*m);
                    drain_outbox(&mut node, &transport);
                }
                Cmd::HasReferenceManifest(id, reply) => {
                    let _ = reply.send(node.has_reference_manifest(id));
                }
                Cmd::TrustOf(subject, reply) => {
                    let trust = node
                        .membership()
                        .get(&subject)
                        .map(|m| m.trust.as_str().to_string());
                    let _ = reply.send(trust);
                }
            }
        }
    });

    AgentHandle {
        cmd: tx,
        id,
        aborts: Arc::new(vec![actor_task.abort_handle(), ticker_task.abort_handle()]),
    }
}

fn drain_outbox(node: &mut Node, transport: &Arc<dyn Transport>) {
    for addressed in node.take_outbox() {
        transport.dispatch(addressed.to, addressed.envelope);
    }
}

fn snapshot(node: &Node) -> Vec<MemberRow> {
    node.membership()
        .iter()
        .map(|m| MemberRow {
            node_id: m.node_id.to_hex(),
            liveness: m.liveness.as_str().to_string(),
            trust: m.trust.as_str().to_string(),
        })
        .collect()
}

fn log_state(node: &Node) -> LogState {
    LogState {
        own_root: hex(&node.own_log_root()),
        replicas: node
            .replica_roots()
            .into_iter()
            .map(|(id, root)| (id.to_hex(), hex(&root)))
            .collect(),
    }
}

// -- in-process transport ----------------------------------------------------

/// A shared switchboard that delivers envelopes between in-process actors by
/// id — the deterministic test transport (no sockets). All agents share one
/// switchboard and register their command channel into it.
#[derive(Clone, Default)]
pub struct ChannelSwitchboard {
    inner: Arc<Mutex<HashMap<NodeId, mpsc::Sender<Cmd>>>>,
}

impl ChannelSwitchboard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a spawned agent so peers can reach it.
    pub fn register(&self, handle: &AgentHandle) {
        self.inner.lock().unwrap().insert(handle.id(), handle.sender());
    }
}

impl Transport for ChannelSwitchboard {
    fn dispatch(&self, to: NodeId, envelope: GossipEnvelope) {
        if let Some(sender) = self.inner.lock().unwrap().get(&to) {
            // Non-blocking: a full/closed peer queue drops the message, which
            // the SWIM failure detector treats as a missed probe.
            let _ = sender.try_send(Cmd::Deliver(Box::new(envelope)));
        }
    }
}

// -- node construction -------------------------------------------------------

/// Derive the [`NodeId`] a peer seeded by `seed` will have in `mesh_id` at
/// `epoch` — mirrors the harness's seed-based identity so a deployment can
/// address peers from a seed list.
pub fn peer_id(mesh_id: &MeshId, epoch: u64, seed: u8) -> NodeId {
    let pubkey = MeshKeypair::from_seed([seed; 32]).public();
    NodeId::derive(mesh_id, Epoch(epoch), &pubkey.fingerprint(), &[seed])
}

/// Build a node (seeded identity + mock backend) that already knows `peers`
/// (their ids) and shares a golden reference with them. Returns the node and
/// its id.
pub fn build_node(
    mesh_id: &MeshId,
    seed: u8,
    role: &str,
    config: NodeConfig,
    peers: &[(NodeId, citadel_mesh::crypto::MeshPublicKey)],
) -> (Node, NodeId) {
    build_node_with_backend(mesh_id, seed, role, config, peers, Box::new(MockBackend::new()))
}

/// Like [`build_node`] but the caller chooses the TPM backend — the binary
/// selects MockBackend (demo), a vTPM, or hardware. The same backend instance
/// later mints the node's TLS identity (E2), so it must be the real device.
pub fn build_node_with_backend(
    mesh_id: &MeshId,
    seed: u8,
    role: &str,
    config: NodeConfig,
    peers: &[(NodeId, citadel_mesh::crypto::MeshPublicKey)],
    backend: Box<dyn TpmBackend>,
) -> (Node, NodeId) {
    let keypair = MeshKeypair::from_seed([seed; 32]);
    let pubkey = keypair.public();
    let id = NodeId::derive(mesh_id, Epoch(config.mesh_epoch), &pubkey.fingerprint(), &[seed]);
    let membership = Membership::new(id, pubkey, role, 0);
    let attestor = Attestor::new(backend).expect("attestor");
    let mut node = Node::new(mesh_id.clone(), id, keypair, membership, attestor, config);
    // Adopt a reference from this node's own (default) measured state so the
    // mesh has a shared golden in the all-mock demo.
    if let Ok(reference) = node.current_reference() {
        node.set_peer_reference(reference);
    }
    for (pid, pkey) in peers {
        if *pid != id {
            node.learn_peer(*pid, *pkey, role, 0);
        }
    }
    (node, id)
}

/// Mint the node's mutual-TLS identity (E2) on the **same** TPM backend that
/// produces its quotes: create a dedicated ECC P-256 key, self-sign a cert in
/// the TPM, and advertise that cert to the mesh (`set_tls_cert`) so peers learn
/// it via enrolment/gossip. Returns the identity, or `None` if the backend
/// can't mint one (e.g. the demo `MockBackend` — the agent then runs plain
/// HTTP). The agent serves mTLS with this identity + `node.tls_roster()`.
pub fn mint_tls_identity(node: &mut Node, common_name: &str) -> Option<tpm_tls::TpmTlsIdentity> {
    use tpm_core::model::{Algorithm, ObjectPath};
    let backend = node.attestor().backend_arc();
    let handle = backend.create_key(Algorithm::EccP256, &ObjectPath::new("tls/agent").ok()?).ok()?;
    let identity = tpm_tls::TpmTlsIdentity::new(backend, handle, common_name).ok()?;
    node.set_tls_cert(identity.certificate().as_ref().to_vec());
    Some(identity)
}

/// The public key a peer seeded by `seed` presents.
pub fn peer_public_key(seed: u8) -> citadel_mesh::crypto::MeshPublicKey {
    MeshKeypair::from_seed([seed; 32]).public()
}
