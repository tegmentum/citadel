//! TLS where the server's private key lives in the TPM.
//!
//! Instead of loading a private key from a PEM file on disk, `tpmd` can use
//! a citadel **identity** whose key is TPM-resident and non-exportable. The
//! private key never leaves the TPM: rustls asks our [`TpmSigningKey`] to
//! sign each TLS handshake, and we forward the signing operation to the TPM
//! via the shared [`TpmBackend`]. Stealing the key off the host is then a
//! non-starter — there is no key on the host to steal.
//!
//! Wiring (see [`crate::run`]): set `TPMD_TLS_IDENTITY=<identity>` and supply
//! the matching certificate (the identity's stored `certificate_pem`, or a
//! `TPMD_TLS_CERT` PEM file). The certificate's public key must correspond to
//! the identity's TPM key.
//!
//! Backend requirement: the signing path needs a backend that returns a real
//! ECDSA `TPMT_SIGNATURE` (the vTPM or a hardware TPM). The software
//! `MockBackend` does not produce real signatures, so it cannot terminate a
//! live TLS handshake — it is fine for the API, not for TPM-backed TLS.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use tpm_core::backend::{KeyHandle, TpmBackend};
use tpm_core::model::Algorithm;
use tpm_core::store::Store;

/// A rustls [`SigningKey`] whose private half is held in the TPM.
struct TpmSigningKey {
    backend: Arc<dyn TpmBackend>,
    handle: KeyHandle,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for TpmSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TpmSigningKey({}, {:?})", self.handle.path, self.scheme)
    }
}

impl SigningKey for TpmSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.scheme).then(|| {
            Box::new(TpmSigner {
                backend: self.backend.clone(),
                handle: self.handle.clone(),
                scheme: self.scheme,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

/// A one-shot signer for a single handshake.
struct TpmSigner {
    backend: Arc<dyn TpmBackend>,
    handle: KeyHandle,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for TpmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TpmSigner({:?})", self.scheme)
    }
}

impl Signer for TpmSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // `backend.sign` hashes the message (SHA-256, matching the
        // ECDSA_NISTP256_SHA256 scheme) and signs it inside the TPM,
        // returning a `TPMT_SIGNATURE`. TLS wants a DER-encoded ECDSA-Sig.
        let tpmt = self
            .backend
            .sign(&self.handle, message)
            .map_err(|e| rustls::Error::General(format!("TPM signing failed: {e}")))?;
        ecdsa_tpmt_to_der(&tpmt).ok_or_else(|| {
            rustls::Error::General(
                "TPM did not return a parseable ECDSA TPMT_SIGNATURE; the TLS \
                 identity needs an ECDSA-capable TPM backend (vTPM/hardware)"
                    .to_string(),
            )
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Resolver that presents one fixed certificate + TPM key for every hello.
#[derive(Debug)]
struct SingleCertResolver {
    certified: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

/// Build a rustls [`ServerConfig`](rustls::ServerConfig) whose server key is
/// the TPM-resident key of `identity_name`, presenting `cert_pem`.
///
/// The private key is never materialized in this process; handshakes are
/// signed by the TPM through `backend`.
pub fn server_config_from_identity(
    store: &Store,
    backend: Arc<dyn TpmBackend>,
    identity_name: &str,
    cert_pem: &str,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    // `ServerConfig::builder()` needs a process-default crypto provider.
    // Install one if the host hasn't already (idempotent; ignore "already
    // set").
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let identity = store
        .get_identity(identity_name)?
        .ok_or_else(|| anyhow::anyhow!("TLS identity not found: {identity_name}"))?;
    let key_obj = store
        .get_object_by_id(&identity.key_object_id)?
        .ok_or_else(|| anyhow::anyhow!("TLS identity '{identity_name}' references a missing key"))?;
    let handle_blob = key_obj
        .handle_blob
        .clone()
        .ok_or_else(|| anyhow::anyhow!("TLS identity '{identity_name}' key has no TPM handle"))?;
    let scheme = scheme_for(key_obj.algorithm)?;
    let handle = KeyHandle {
        id: handle_blob,
        path: key_obj.path.to_string(),
    };

    let certs = parse_certs(cert_pem)?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in the TLS cert PEM for identity '{identity_name}'");
    }

    let signing_key: Arc<dyn SigningKey> = Arc::new(TpmSigningKey {
        backend,
        handle,
        scheme,
    });
    let certified = Arc::new(CertifiedKey::new(certs, signing_key));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertResolver { certified }));
    Ok(Arc::new(config))
}

/// Map a citadel key algorithm to the TLS signature scheme it signs with.
fn scheme_for(alg: Algorithm) -> anyhow::Result<SignatureScheme> {
    match alg {
        Algorithm::EccP256 => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
        other => anyhow::bail!(
            "TLS-from-TPM currently supports ecc-p256 identities, not {other:?}"
        ),
    }
}

fn parse_certs(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut rd).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

// -- TPMT_SIGNATURE → DER ECDSA-Sig-Value ------------------------------------

/// Convert a TPM `TPMT_SIGNATURE` (ECDSA) into the ASN.1 DER `ECDSA-Sig-Value`
/// (`SEQUENCE { INTEGER r, INTEGER s }`) that TLS expects. Returns `None` if
/// the bytes are not a well-formed ECDSA `TPMT_SIGNATURE`.
///
/// `TPMT_SIGNATURE` (ECDSA) layout:
/// `sigAlg(2) ‖ hashAlg(2) ‖ TPM2B r(size(2)‖bytes) ‖ TPM2B s(size(2)‖bytes)`.
fn ecdsa_tpmt_to_der(sig: &[u8]) -> Option<Vec<u8>> {
    const TPM_ALG_ECDSA: u16 = 0x0018;
    if sig.len() < 6 {
        return None;
    }
    let sig_alg = u16::from_be_bytes([sig[0], sig[1]]);
    if sig_alg != TPM_ALG_ECDSA {
        return None;
    }
    // sig[2..4] = hashAlg (unused here).
    let r_size = u16::from_be_bytes([sig[4], sig[5]]) as usize;
    let r_start = 6usize;
    let r_end = r_start.checked_add(r_size)?;
    if sig.len() < r_end + 2 {
        return None;
    }
    let r = &sig[r_start..r_end];
    let s_size = u16::from_be_bytes([sig[r_end], sig[r_end + 1]]) as usize;
    let s_start = r_end + 2;
    let s_end = s_start.checked_add(s_size)?;
    if sig.len() < s_end || r.is_empty() || s_size == 0 {
        return None;
    }
    let s = &sig[s_start..s_end];
    Some(der_ecdsa_sig(r, s))
}

/// DER-encode an ASN.1 `INTEGER` from a big-endian unsigned magnitude,
/// stripping leading zero bytes and prepending `0x00` when the high bit is
/// set (so it stays positive).
fn der_uint(mut b: &[u8]) -> Vec<u8> {
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let mut out = vec![0x02u8];
    if b.first().is_some_and(|f| f & 0x80 != 0) {
        out.push((b.len() + 1) as u8);
        out.push(0x00);
    } else {
        out.push(b.len() as u8);
    }
    out.extend_from_slice(b);
    out
}

/// `SEQUENCE { INTEGER r, INTEGER s }`. For P-256 the body is < 128 bytes, so
/// a single-byte length suffices.
fn der_ecdsa_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = der_uint(r);
    body.extend(der_uint(s));
    let mut out = vec![0x30u8, body.len() as u8];
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic ECDSA `TPMT_SIGNATURE` with the given r/s bytes.
    fn tpmt(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x0018u16.to_be_bytes()); // sigAlg = ECDSA
        v.extend_from_slice(&0x000Bu16.to_be_bytes()); // hashAlg = SHA-256
        v.extend_from_slice(&(r.len() as u16).to_be_bytes());
        v.extend_from_slice(r);
        v.extend_from_slice(&(s.len() as u16).to_be_bytes());
        v.extend_from_slice(s);
        v
    }

    #[test]
    fn converts_tpmt_to_well_formed_der() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let der = ecdsa_tpmt_to_der(&tpmt(&r, &s)).expect("parses");
        assert_eq!(der[0], 0x30, "SEQUENCE");
        assert_eq!(der[1] as usize, der.len() - 2, "length covers the body");
        // Two INTEGERs of 32 bytes each (no high bit): 0x02 0x20 … twice.
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 0x20);
        assert_eq!(der[2 + 34], 0x02);
        assert_eq!(der[2 + 34 + 1], 0x20);
    }

    #[test]
    fn high_bit_integer_gets_zero_prefix() {
        // r has its top bit set → DER must prepend 0x00 to keep it positive.
        let mut r = [0u8; 32];
        r[0] = 0x80;
        let s = [0x01u8; 32];
        let der = ecdsa_tpmt_to_der(&tpmt(&r, &s)).unwrap();
        // First INTEGER: 0x02, len 0x21 (33), 0x00, 0x80, …
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 0x21);
        assert_eq!(der[4], 0x00);
        assert_eq!(der[5], 0x80);
    }

    #[test]
    fn rejects_non_ecdsa_and_truncated() {
        // Wrong sigAlg (RSASSA = 0x0014).
        let mut bad = tpmt(&[1u8; 32], &[2u8; 32]);
        bad[0] = 0x00;
        bad[1] = 0x14;
        assert!(ecdsa_tpmt_to_der(&bad).is_none());

        // Truncated.
        assert!(ecdsa_tpmt_to_der(&[0x00, 0x18, 0x00]).is_none());

        // The mock backend's 8-byte non-signature must not parse.
        assert!(ecdsa_tpmt_to_der(&[0u8; 8]).is_none());
    }

    #[test]
    fn scheme_mapping() {
        assert_eq!(
            scheme_for(Algorithm::EccP256).unwrap(),
            SignatureScheme::ECDSA_NISTP256_SHA256
        );
        assert!(scheme_for(Algorithm::Rsa2048).is_err());
    }

    #[test]
    fn missing_identity_is_an_error() {
        let store = Store::open_memory().unwrap();
        let backend: Arc<dyn TpmBackend> =
            Arc::new(tpm_core::backend::MockBackend::new());
        let err = server_config_from_identity(&store, backend, "nope", "")
            .expect_err("unknown identity");
        assert!(err.to_string().contains("TLS identity not found"));
    }
}
