//! `citadel-agent` — run one mesh node as a networked process.
//!
//! Configuration is via environment variables (a demo-grade launcher):
//!
//! * `CITADEL_MESH_ID`   — mesh/trust domain (default `citadel`)
//! * `CITADEL_SEED`      — this node's identity seed, 0–255 (required)
//! * `CITADEL_ROLE`      — node role (default `worker`)
//! * `CITADEL_LISTEN`    — HTTP listen address (default `127.0.0.1:7800`)
//! * `CITADEL_TICK_MS`   — SWIM tick interval in ms (default `500`)
//! * `CITADEL_PEERS`     — JSON `[[seed, "http://host:port"], ...]` of peers
//! * `CITADEL_TPM_BACKEND` — `mock` (default) | `tcti` (`--features tpm-hw`) |
//!   `vtpm` (`--features vtpm`); see [`make_backend`] for the per-backend env.
//!
//! Peer ids are derived from their seeds (the same seed-based identity the
//! mesh harness uses), so the launcher can address peers without a registry.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use citadel_agent::http::{mtls_client, router, serve_mtls, HttpTransport};
use citadel_agent::{
    build_node_with_backend, mint_tls_identity, peer_id, peer_public_key, spawn_node,
};
use citadel_mesh::id::MeshId;
use citadel_mesh::node::NodeConfig;
use citadel_mesh::NodeId;
use tpm_core::backend::{MockBackend, TpmBackend};

/// Select this agent's TPM backend (the binary owns this choice). Chosen by
/// `CITADEL_TPM_BACKEND`:
///   * unset / `mock` — in-process `MockBackend` (demo; can't sign real TLS, so
///     the agent runs plain HTTP).
///   * `tcti` — a real TPM via tss-esapi (build `--features tpm-hw`): set
///     `CITADEL_TPM_TCTI`, e.g. `device:/dev/tpmrm0` (hardware) or
///     `swtpm:path=/run/swtpm.sock` / `swtpm:host=127.0.0.1,port=2321` (swtpm).
///   * `vtpm` — in-process libtpms vTPM (build `--features vtpm`): set
///     `TPM_VTPM_COMPONENT` (a built `*.component.wasm`) and `CITADEL_VTPM_STATE`
///     (a persisted state file — an ephemeral vTPM can't mint/sign).
///
/// A real backend signs for real, enabling mutual TLS (E2). A selected backend
/// that is unavailable (feature off, missing env, init error) logs why and falls
/// back to the mock, so the agent always starts.
fn make_backend() -> Box<dyn TpmBackend> {
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

/// Read this node's own measured state from securityfs (firmware log + IMA list)
/// and stage it into the node's evidence (B1/C1). Absent logs (no measured boot
/// / IMA inactive) and read errors (e.g. not running as root) are tolerated so
/// the agent still starts. Paths are overridable via `CITADEL_FIRMWARE_EVENT_LOG`
/// / `CITADEL_IMA_RUNTIME_LIST` — point them at a captured fixture off a real
/// node to dry-run without a live securityfs.
fn stage_node_logs(node: &mut citadel_mesh::node::Node) {
    let firmware = tpm_core::sys::read_firmware_event_log().unwrap_or_else(|e| {
        tracing::warn!("reading firmware event log: {e}");
        None
    });
    let ima = tpm_core::sys::read_ima_runtime_list().unwrap_or_else(|e| {
        tracing::warn!("reading IMA runtime list: {e}");
        None
    });
    let (fw_events, ima_entries) =
        citadel_agent::stage_node_logs(node, firmware.as_deref(), ima.as_deref());
    tracing::info!("staged measured state: {fw_events} firmware events, {ima_entries} IMA entries");
}

/// Parse `CITADEL_PEER_CERTS` (JSON `[[seed, "hex-DER"], …]`) into the pinnable
/// peer roster for mutual TLS — the out-of-band cert distribution for the static
/// launcher (enrolment/gossip distributes them at runtime otherwise).
fn parse_peer_certs(mesh_id: &MeshId, epoch: u64) -> Vec<tpm_tls::CertificateDer<'static>> {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mesh_id =
        MeshId::new(std::env::var("CITADEL_MESH_ID").unwrap_or_else(|_| "citadel".into()));
    let seed: u8 = std::env::var("CITADEL_SEED")
        .map_err(|_| anyhow::anyhow!("CITADEL_SEED is required (0-255)"))?
        .parse()?;
    let role = std::env::var("CITADEL_ROLE").unwrap_or_else(|_| "worker".into());
    let listen = std::env::var("CITADEL_LISTEN").unwrap_or_else(|_| "127.0.0.1:7800".into());
    let tick_ms: u64 = std::env::var("CITADEL_TICK_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let peers_cfg: Vec<(u8, String)> =
        serde_json::from_str(&std::env::var("CITADEL_PEERS").unwrap_or_else(|_| "[]".into()))?;

    let epoch = 1u64;
    let config = NodeConfig {
        mesh_epoch: epoch,
        ..NodeConfig::default()
    };

    // Resolve peers' ids + keys from their seeds.
    let peers: Vec<(NodeId, _)> = peers_cfg
        .iter()
        .map(|(s, _)| (peer_id(&mesh_id, epoch, *s), peer_public_key(*s)))
        .collect();
    let url_map: HashMap<NodeId, String> = peers_cfg
        .iter()
        .map(|(s, url)| (peer_id(&mesh_id, epoch, *s), url.clone()))
        .collect();

    let (mut node, id) =
        build_node_with_backend(&mesh_id, seed, &role, config, &peers, make_backend());

    // B1/C1: ship this node's real measured state (firmware log + IMA list) read
    // from its own /sys, so its evidence carries what actually booted and ran.
    stage_node_logs(&mut node);

    // E2: mint a mutual-TLS identity on this node's TPM, if the backend can
    // (the demo MockBackend can't → `None` → plain HTTP). Peers learn our cert
    // via enrolment/gossip; we pin theirs from `CITADEL_PEER_CERTS` (launcher)
    // or `node.tls_roster()` at runtime.
    let tls_identity = mint_tls_identity(&mut node, &id.to_string());
    let peer_certs = parse_peer_certs(&mesh_id, epoch);
    let mtls = tls_identity.as_ref().filter(|_| !peer_certs.is_empty());

    let transport = match &mtls {
        Some(identity) => {
            tracing::info!("citadel-agent {id} (seed {seed}) mutual-TLS on {listen}");
            Arc::new(HttpTransport::with_client(
                url_map,
                mtls_client(identity, peer_certs.clone())?,
            ))
        }
        None => {
            tracing::info!("citadel-agent {id} (seed {seed}) plain HTTP on {listen}");
            Arc::new(HttpTransport::new(url_map))
        }
    };
    let handle = spawn_node(node, transport, Duration::from_millis(tick_ms));
    let app = router(handle);

    match mtls {
        Some(identity) => {
            let addr: std::net::SocketAddr = listen.parse()?;
            serve_mtls(app, addr, identity, peer_certs).await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
