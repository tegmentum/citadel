//! E2 — a real mutual-TLS handshake between two agents whose keys live in the
//! TPM. Each side mints its own self-signed cert (the TPM signs it), the
//! handshake is signed inside the TPM, and peers are authenticated by pinning
//! the exact certificate. Runs against the real vTPM component, which signs for
//! real with **persisted** state (the ephemeral vTPM returns a non-signature
//! fallback, so a state file is required). Skipped unless TPM_VTPM_COMPONENT
//! is set.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use tpm_core::backend::TpmBackend;
use tpm_core::model::{Algorithm, ObjectPath};
use tpm_tls::TpmTlsIdentity;
use vtpm_backend::VtpmBackend;

/// Mint a TPM-backed TLS identity on a fresh persisted vTPM.
fn identity(seed: &str, cn: &str) -> Option<TpmTlsIdentity> {
    let component = std::env::var("TPM_VTPM_COMPONENT").ok()?;
    let dir = std::env::temp_dir().join(format!("tpm-tls-{seed}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.bin");
    let _ = std::fs::remove_file(&state);
    let backend = VtpmBackend::open(std::path::Path::new(&component), Some(&state)).unwrap();
    let handle = backend
        .create_key(Algorithm::EccP256, &ObjectPath::new(&format!("tls/{seed}")).unwrap())
        .unwrap();
    let backend: Arc<dyn TpmBackend> = Arc::new(backend);
    match TpmTlsIdentity::new(backend, handle, cn) {
        Ok(id) => Some(id),
        Err(e) => panic!("minting TPM TLS identity failed: {e}"),
    }
}

/// Drive a rustls client+server handshake to completion over in-memory buffers.
fn complete_handshake(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    server_name: &str,
) -> Result<(), rustls::Error> {
    let name = ServerName::try_from(server_name.to_string()).unwrap();
    let mut c = rustls::ClientConnection::new(client, name).unwrap();
    let mut s = rustls::ServerConnection::new(server).unwrap();

    // Pump handshake data between the two until both are done (or one errors).
    for _ in 0..20 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            c.read_tls(&mut buf.as_slice()).unwrap();
            c.process_new_packets()?;
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(());
        }
    }
    Err(rustls::Error::General("handshake did not converge".into()))
}

#[test]
fn two_tpm_identities_complete_mutual_tls() {
    let Some(alice) = identity("alice", "alice.mesh") else {
        eprintln!("skipping: TPM_VTPM_COMPONENT not set");
        return;
    };
    let bob = identity("bob", "bob.mesh").unwrap();

    // Each pins the other's certificate (the mesh identity exchange).
    let server = bob.server_config(&[alice.certificate().clone()]).unwrap();
    let client = alice.client_config(bob.certificate().clone()).unwrap();

    complete_handshake(client, server, "bob.mesh")
        .expect("mutual TLS between two TPM-held identities succeeds");
}

#[test]
fn an_unpinned_client_is_rejected() {
    let Some(alice) = identity("alice2", "alice.mesh") else {
        eprintln!("skipping: TPM_VTPM_COMPONENT not set");
        return;
    };
    let bob = identity("bob2", "bob.mesh").unwrap();
    let mallory = identity("mallory", "mallory.mesh").unwrap();

    // Bob pins only Alice; Mallory (a valid TPM identity, but unpinned) connects.
    let server = bob.server_config(&[alice.certificate().clone()]).unwrap();
    let client = mallory.client_config(bob.certificate().clone()).unwrap();

    let result = complete_handshake(client, server, "bob.mesh");
    assert!(result.is_err(), "an unpinned client must be rejected by mutual-TLS pinning");
}

#[test]
fn an_impostor_server_cert_is_rejected() {
    let Some(alice) = identity("alice3", "alice.mesh") else {
        eprintln!("skipping: TPM_VTPM_COMPONENT not set");
        return;
    };
    let bob = identity("bob3", "bob.mesh").unwrap();
    let mallory = identity("mallory3", "mallory.mesh").unwrap();

    // Alice expects Bob but Mallory answers presenting her own cert. Alice
    // pinned Bob's cert, so the server cert check fails.
    let server = mallory.server_config(&[alice.certificate().clone()]).unwrap();
    let client = alice.client_config(bob.certificate().clone()).unwrap();

    let fake_bob: CertificateDer<'static> = mallory.certificate().clone();
    assert_ne!(fake_bob.as_ref(), bob.certificate().as_ref());

    let result = complete_handshake(client, server, "bob.mesh");
    assert!(result.is_err(), "a server presenting an unpinned cert must be rejected");
}
