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
use citadel_mesh::membership::{MemberUpdate, Membership};
use citadel_mesh::node::{Node, NodeConfig};
use citadel_mesh::quarantine::OperatorQuarantineApproval;
use citadel_mesh::reference::ReferenceManifest;
use citadel_mesh::types::{AttestationResult, GossipEnvelope};
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
    ObserverFeed(oneshot::Sender<ObserverFeed>),
    RelayQuarantineApproval(Box<OperatorQuarantineApproval>),
    BroadcastApp([u8; 32], Vec<u8>),
    DrainApp([u8; 32], oneshot::Sender<Vec<Vec<u8>>>),
}

/// One pull of an observer node's verified state for the control plane (CP7
/// daemon): the mesh params + every known member + the verified verdicts
/// received since the last pull. Feeds `ControlPlane::ingest_observer_feed`.
#[derive(Clone, Debug, Default)]
pub struct ObserverFeed {
    pub epoch: u64,
    pub witness_count: usize,
    pub members: Vec<MemberUpdate>,
    pub verdicts: Vec<AttestationResult>,
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

    /// Pull this (observer) node's verified state for the control plane (CP7
    /// daemon): mesh params + members + the verdicts received since the last
    /// pull (which it drains). Empty on a non-observer node.
    pub async fn observer_feed(&self) -> ObserverFeed {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::ObserverFeed(tx)).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            ObserverFeed::default()
        }
    }

    /// Broadcast an app-layer relay message on `topic` (e.g. an MSS threshold-
    /// signing round message), opaque to the mesh.
    pub async fn broadcast_app(&self, topic: [u8; 32], payload: Vec<u8>) {
        let _ = self.cmd.send(Cmd::BroadcastApp(topic, payload)).await;
    }

    /// Drain the app-relay payloads received on `topic` since the last call.
    pub async fn drain_app(&self, topic: [u8; 32]) -> Vec<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::DrainApp(topic, tx)).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Relay a trusted operator's quarantine approval into the mesh (CP5).
    pub async fn relay_quarantine_approval(&self, approval: OperatorQuarantineApproval) {
        let _ = self
            .cmd
            .send(Cmd::RelayQuarantineApproval(Box::new(approval)))
            .await;
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
        let _ = self
            .cmd
            .send(Cmd::SetReferenceAuthorities(Box::new(authorities)))
            .await;
    }

    /// Adopt a signed reference manifest locally (no gossip) — for seeding one
    /// node so anti-entropy spreads it to the rest.
    pub async fn apply_reference_manifest(&self, manifest: ReferenceManifest) {
        let _ = self
            .cmd
            .send(Cmd::ApplyReferenceManifest(Box::new(manifest)))
            .await;
    }

    /// Adopt a signed reference manifest and gossip it to peers.
    pub async fn broadcast_reference_manifest(&self, manifest: ReferenceManifest) {
        let _ = self
            .cmd
            .send(Cmd::BroadcastReferenceManifest(Box::new(manifest)))
            .await;
    }

    /// Whether this node has adopted the manifest with content id `id`.
    pub async fn has_reference_manifest(&self, id: [u8; 32]) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd
            .send(Cmd::HasReferenceManifest(id, tx))
            .await
            .is_ok()
        {
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
                Cmd::ObserverFeed(reply) => {
                    let feed = ObserverFeed {
                        epoch: node.mesh_epoch(),
                        witness_count: node.witness_count(),
                        members: node.membership().iter().map(|m| m.update()).collect(),
                        verdicts: node.drain_observed_verdicts(),
                    };
                    let _ = reply.send(feed);
                }
                Cmd::RelayQuarantineApproval(approval) => {
                    node.relay_quarantine_approval(*approval);
                    drain_outbox(&mut node, &transport);
                }
                Cmd::BroadcastApp(topic, payload) => {
                    node.broadcast_app(topic, payload);
                    drain_outbox(&mut node, &transport);
                }
                Cmd::DrainApp(topic, reply) => {
                    let _ = reply.send(node.drain_app(topic));
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
        self.inner
            .lock()
            .unwrap()
            .insert(handle.id(), handle.sender());
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
    build_node_with_backend(
        mesh_id,
        seed,
        role,
        config,
        peers,
        Box::new(MockBackend::new()),
    )
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
    let id = NodeId::derive(
        mesh_id,
        Epoch(config.mesh_epoch),
        &pubkey.fingerprint(),
        &[seed],
    );
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

/// Stage this node's own measured state into the evidence it produces: the
/// firmware measured-boot log (B1) and the IMA runtime list (C1). Both ship in
/// attestation evidence and are preserved in the node's LtHash log. The args are
/// the bytes/text already read from securityfs (`tpm_core::sys`) or a captured
/// fixture — `None` means the node has no such log. An unparseable firmware log
/// is dropped (not shipped). Returns `(firmware_events, ima_entries)` ingested.
pub fn stage_node_logs(
    node: &mut Node,
    firmware_log: Option<&[u8]>,
    ima_list: Option<&str>,
) -> (usize, usize) {
    // Firmware (B1): only ship a log that parses, so a node never gossips a
    // garbage event log. `stage_event_log` ships the raw bytes in evidence;
    // `ingest_own_event_log` preserves each event in the LtHash log.
    let firmware_events = match firmware_log {
        Some(bytes) => match node.ingest_own_event_log(bytes) {
            Ok(n) => {
                node.stage_event_log(bytes);
                n
            }
            Err(_) => 0,
        },
        None => 0,
    };
    // IMA (C1): stage the list to ship in evidence and preserve it in the log.
    let ima_entries = match ima_list {
        Some(ima) => {
            node.stage_ima(ima);
            node.ingest_own_ima(ima).1
        }
        None => 0,
    };
    (firmware_events, ima_entries)
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
    let handle = backend
        .create_key(Algorithm::EccP256, &ObjectPath::new("tls/agent").ok()?)
        .ok()?;
    let identity = tpm_tls::TpmTlsIdentity::new(backend, handle, common_name).ok()?;
    node.set_tls_cert(identity.certificate().as_ref().to_vec());
    Some(identity)
}

/// Mint this node's mesh-TLS identity **only if the mesh authorized its release**
/// (MSS5): the identity is a secret class
/// ([`identity_secret_id`](citadel_mesh::release::identity_secret_id)) the node
/// requests like any secret, so a node the mesh no longer trusts cannot mint (or
/// renew) its service identity. `identity_request_id` is the node's pending
/// release request for that secret. Returns `None` if the release isn't
/// authorized (refused without even minting) or the backend can't sign. The key
/// stays TPM-held.
pub fn mint_mesh_identity(
    node: &mut Node,
    common_name: &str,
    identity_request_id: [u8; 32],
    now: u64,
) -> Option<tpm_tls::TpmTlsIdentity> {
    if !node.release_authorized(identity_request_id, now) {
        return None; // the mesh has not authorized this node's identity
    }
    mint_tls_identity(node, common_name)
}

/// The public key a peer seeded by `seed` presents.
pub fn peer_public_key(seed: u8) -> citadel_mesh::crypto::MeshPublicKey {
    MeshKeypair::from_seed([seed; 32]).public()
}

/// Select this node's TPM backend from `CITADEL_TPM_BACKEND`
/// (`mock` | `tcti` | `vtpm`), falling back to the in-process mock if a real
/// backend is unavailable. Shared by the agent and the control-plane daemon.
pub fn make_backend() -> Box<dyn TpmBackend> {
    match std::env::var("CITADEL_TPM_BACKEND").ok().as_deref() {
        None | Some("") | Some("mock") => Box::new(MockBackend::new()),
        Some(kind) => make_real_backend(kind).unwrap_or_else(|e| {
            tracing::warn!("TPM backend '{kind}' unavailable ({e}); falling back to mock");
            Box::new(MockBackend::new())
        }),
    }
}

/// Build the real backend named by `kind`, or an error explaining why it is
/// unavailable (so the caller can fall back to the mock).
fn make_real_backend(kind: &str) -> anyhow::Result<Box<dyn TpmBackend>> {
    match kind {
        "tcti" => make_tcti_backend(),
        "vtpm" => make_vtpm_backend(),
        other => anyhow::bail!("unknown CITADEL_TPM_BACKEND '{other}' (mock|tcti|vtpm)"),
    }
}

#[cfg(feature = "tpm-hw")]
fn make_tcti_backend() -> anyhow::Result<Box<dyn TpmBackend>> {
    let tcti = std::env::var("CITADEL_TPM_TCTI")
        .map_err(|_| anyhow::anyhow!("set CITADEL_TPM_TCTI (e.g. device:/dev/tpmrm0)"))?;
    let backend = tpm_core::backend::HardwareBackend::new_from_tcti_str(&tcti)?;
    tracing::info!("TPM backend: tss-esapi via TCTI '{tcti}'");
    Ok(Box::new(backend))
}

#[cfg(not(feature = "tpm-hw"))]
fn make_tcti_backend() -> anyhow::Result<Box<dyn TpmBackend>> {
    anyhow::bail!("the tcti backend needs a build with --features tpm-hw")
}

#[cfg(feature = "vtpm")]
fn make_vtpm_backend() -> anyhow::Result<Box<dyn TpmBackend>> {
    let component = std::env::var("TPM_VTPM_COMPONENT")
        .map_err(|_| anyhow::anyhow!("set TPM_VTPM_COMPONENT to a built vTPM *.component.wasm"))?;
    let state = std::env::var("CITADEL_VTPM_STATE").map_err(|_| {
        anyhow::anyhow!(
            "set CITADEL_VTPM_STATE to a persisted state file (an ephemeral vTPM can't sign)"
        )
    })?;
    let backend = vtpm_backend::VtpmBackend::open(
        std::path::Path::new(&component),
        Some(std::path::Path::new(&state)),
    )?;
    tracing::info!("TPM backend: in-process vTPM (state {state})");
    Ok(Box::new(backend))
}

#[cfg(not(feature = "vtpm"))]
fn make_vtpm_backend() -> anyhow::Result<Box<dyn TpmBackend>> {
    anyhow::bail!("the vtpm backend needs a build with --features vtpm")
}

/// Parse peer mutual-TLS certificates from `CITADEL_PEER_CERTS`
/// (JSON `[[seed,"<DER hex>"],…]`) for pinning. Shared by the agent + daemon.
pub fn parse_peer_certs(mesh_id: &MeshId, epoch: u64) -> Vec<tpm_tls::CertificateDer<'static>> {
    let raw = std::env::var("CITADEL_PEER_CERTS").unwrap_or_else(|_| "[]".into());
    let entries: Vec<(u8, String)> = serde_json::from_str(&raw).unwrap_or_default();
    entries
        .iter()
        .filter_map(|(seed, hex)| {
            let _ = peer_id(mesh_id, epoch, *seed); // validate addressable
            let der = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            Some(tpm_tls::CertificateDer::from(der))
        })
        .collect()
}
