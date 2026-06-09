//! go-plugin **AutoMTLS** for the external plugin. When SPIRE launches a plugin
//! with AutoMTLS it passes its client certificate in `PLUGIN_CLIENT_CERT` and
//! expects the plugin to (1) serve mTLS presenting an ephemeral cert, requiring +
//! verifying a client cert signed by that CA, and (2) advertise its server cert
//! as the 6th handshake field (base64 RawStdEncoding of the DER leaf). This is
//! that handshake, on the project's rustls/aws-lc-rs provider.

use std::sync::Arc;

use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// A built server-side mTLS config + the DER leaf to advertise in the handshake.
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    pub cert_der: Vec<u8>,
}

/// Build the AutoMTLS server config: an ephemeral self-signed server cert, and a
/// client-cert verifier rooted at the host's `PLUGIN_CLIENT_CERT`.
pub fn build(client_ca_pem: &str) -> anyhow::Result<ServerTls> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Ephemeral server identity.
    let key = rcgen::KeyPair::generate()?;
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])?.self_signed(&key)?;
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();

    // Trust only the host's client cert (AutoMTLS uses it as the CA).
    let mut roots = rustls::RootCertStore::empty();
    let mut rd = client_ca_pem.as_bytes();
    for c in rustls_pemfile::certs(&mut rd) {
        roots.add(c?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::try_from(key_der).map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;
    Ok(ServerTls {
        config: Arc::new(config),
        cert_der,
    })
}

/// The 6th handshake field: base64 (RawStdEncoding, no padding) of the server
/// cert DER — go-plugin pins the plugin's cert from this.
pub fn handshake_cert_field(cert_der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(cert_der)
}
