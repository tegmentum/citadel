//! E2 end-to-end — the agent's HTTP gossip transport over mutual TLS with
//! TPM-held keys. A real axum server (TPM identity, pinning the client) and a
//! real reqwest client (TPM identity, pinning the server) exchange a POST over
//! TCP; an unpinned client is refused. Runs against the real vTPM (persisted,
//! so it signs for real); skipped unless TPM_VTPM_COMPONENT is set.
//!
//! Requires the `vtpm` feature (which pulls the vtpm-backend dependency):
//!   TPM_VTPM_COMPONENT=… cargo test -p citadel-agent --features vtpm --test mtls_transport
#![cfg(feature = "vtpm")]

use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use axum::Router;
use citadel_agent::http::{mtls_client, serve_mtls};
use tpm_core::backend::TpmBackend;
use tpm_core::model::{Algorithm, ObjectPath};
use tpm_tls::TpmTlsIdentity;
use vtpm_backend::VtpmBackend;

fn identity(seed: &str, cn: &str) -> Option<TpmTlsIdentity> {
    let component = std::env::var("TPM_VTPM_COMPONENT").ok()?;
    let dir = std::env::temp_dir().join(format!("agent-mtls-{seed}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.bin");
    let _ = std::fs::remove_file(&state);
    let backend = VtpmBackend::open(std::path::Path::new(&component), Some(&state)).unwrap();
    let handle = backend
        .create_key(
            Algorithm::EccP256,
            &ObjectPath::new(&format!("tls/{seed}")).unwrap(),
        )
        .unwrap();
    let backend: Arc<dyn TpmBackend> = Arc::new(backend);
    Some(TpmTlsIdentity::new(backend, handle, cn).expect("mint TPM TLS identity"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gossip_flows_over_mutual_tls_and_unpinned_is_refused() {
    let Some(server_id) = identity("server", "server.mesh") else {
        eprintln!("skipping: TPM_VTPM_COMPONENT not set");
        return;
    };
    let client_id = identity("client", "client.mesh").unwrap();
    let stranger = identity("stranger", "stranger.mesh").unwrap();

    let server_cert = server_id.certificate().clone();
    let client_cert = client_id.certificate().clone();

    // Server: present server_id, accept only the pinned client.
    let port = free_port();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let app = Router::new().route(
        "/v1/gossip",
        post(|| async { axum::http::StatusCode::ACCEPTED }),
    );
    tokio::spawn(async move {
        let _ = serve_mtls(app, addr, &server_id, vec![client_cert]).await;
    });
    // Wait for the listener to come up.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let url = format!("https://127.0.0.1:{port}/v1/gossip");

    // Pinned client → accepted.
    let client = mtls_client(&client_id, vec![server_cert.clone()]).unwrap();
    let mut ok = None;
    for _ in 0..10 {
        match client.post(&url).json(&serde_json::json!({})).send().await {
            Ok(r) => {
                ok = Some(r.status());
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    assert_eq!(
        ok,
        Some(reqwest::StatusCode::ACCEPTED),
        "a pinned mesh peer completes mutual TLS and its gossip POST is accepted"
    );

    // Unpinned client (the server never pinned `stranger`) → handshake refused.
    let bad = mtls_client(&stranger, vec![server_cert]).unwrap();
    let result = bad.post(&url).json(&serde_json::json!({})).send().await;
    assert!(
        result.is_err(),
        "the server must refuse a client whose cert it did not pin"
    );
}
