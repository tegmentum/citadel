//! Certificate **pinning** verifiers — mesh identity is the exact peer
//! certificate (which embeds the TPM key), not a CA chain. A peer is accepted
//! iff its end-entity certificate is one we pinned; the handshake signature is
//! still verified (delegated to the default crypto provider) so pinning proves
//! the peer actually holds the matching TPM private key.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

fn provider_algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
}

fn is_pinned(pinned: &[CertificateDer<'static>], ee: &CertificateDer<'_>) -> bool {
    pinned.iter().any(|p| p.as_ref() == ee.as_ref())
}

/// Client-side: accept a server only if its cert is pinned.
#[derive(Debug)]
pub struct PinnedServerAuth {
    pinned: Vec<CertificateDer<'static>>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedServerAuth {
    pub fn new(pinned: Vec<CertificateDer<'static>>) -> Self {
        Self { pinned, algs: provider_algs() }
    }
}

impl ServerCertVerifier for PinnedServerAuth {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if is_pinned(&self.pinned, end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("server certificate is not a pinned mesh peer".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Server-side: require client auth and accept a client only if its cert is
/// pinned.
#[derive(Debug)]
pub struct PinnedClientAuth {
    pinned: Vec<CertificateDer<'static>>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedClientAuth {
    pub fn new(pinned: Vec<CertificateDer<'static>>) -> Self {
        Self { pinned, algs: provider_algs() }
    }
}

impl ClientCertVerifier for PinnedClientAuth {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if is_pinned(&self.pinned, end_entity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General("client certificate is not a pinned mesh peer".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Presents one fixed (TPM-backed) certificate as the server.
#[derive(Debug)]
pub(crate) struct SingleCert {
    pub certified: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SingleCert {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

/// Presents one fixed (TPM-backed) certificate as the client.
#[derive(Debug)]
pub(crate) struct SingleClientCert {
    pub certified: Arc<CertifiedKey>,
}

impl ResolvesClientCert for SingleClientCert {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
