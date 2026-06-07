//! TLS identities whose private key never leaves the TPM (roadmap E2).
//!
//! Agents authenticate to each other with **mutual TLS** where each side's key
//! is TPM-resident: the TPM mints its own self-signed certificate (via
//! `rcgen`'s remote-signing seam) and signs every handshake. Peers are
//! authenticated by **pinning the exact certificate** (mesh identity = the
//! cert, which embeds the TPM key) — there is no public CA; the mesh enrolment
//! layer distributes peer certs.
//!
//! This crate is backend-agnostic ([`tpm_core::backend::TpmBackend`]); it works
//! with the vTPM, swtpm, or hardware. The key must be ECC P-256 (the TLS
//! identity scheme is `ecdsa_secp256r1_sha256`).

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use tpm_core::backend::{KeyHandle, TpmBackend};

mod verify;
pub use verify::{PinnedClientAuth, PinnedServerAuth};

/// A TLS identity backed by a TPM-resident ECC P-256 key: the self-signed
/// certificate it presents, plus the means to sign handshakes inside the TPM.
#[derive(Clone)]
pub struct TpmTlsIdentity {
    cert: CertificateDer<'static>,
    backend: Arc<dyn TpmBackend>,
    handle: KeyHandle,
}

impl TpmTlsIdentity {
    /// Mint a fresh self-signed certificate for the TPM key at `handle`,
    /// signed *by that key inside the TPM*. `subject_cn` becomes the cert's
    /// common name + SAN (the node identity). The key must be ECC P-256.
    pub fn new(
        backend: Arc<dyn TpmBackend>,
        handle: KeyHandle,
        subject_cn: &str,
    ) -> anyhow::Result<Self> {
        let point = parse_ecc_point(&backend.public_blob(&handle)?)?;
        let remote = TpmRemoteKeyPair { backend: backend.clone(), handle: handle.clone(), point };
        let key_pair = rcgen::KeyPair::from_remote(Box::new(remote))
            .map_err(|e| anyhow::anyhow!("rcgen rejected the TPM key: {e}"))?;

        let mut params = rcgen::CertificateParams::new(vec![subject_cn.to_string()])
            .map_err(|e| anyhow::anyhow!("cert params: {e}"))?;
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, subject_cn);
            dn
        };
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| anyhow::anyhow!("TPM self-signing the cert failed: {e}"))?;
        let cert = CertificateDer::from(cert.der().to_vec());
        Ok(TpmTlsIdentity { cert, backend, handle })
    }

    /// The DER certificate this identity presents — pin this on peers.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    fn certified_key(&self) -> Arc<CertifiedKey> {
        let signing: Arc<dyn SigningKey> = Arc::new(TpmSigningKey {
            backend: self.backend.clone(),
            handle: self.handle.clone(),
            scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
        });
        Arc::new(CertifiedKey::new(vec![self.cert.clone()], signing))
    }

    /// A **mutual-TLS server** config: presents this TPM identity and accepts a
    /// client only if its certificate is one of `pinned_clients`.
    pub fn server_config(
        &self,
        pinned_clients: &[CertificateDer<'static>],
    ) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        install_provider();
        let verifier = Arc::new(PinnedClientAuth::new(pinned_clients.to_vec()));
        let resolver = Arc::new(verify::SingleCert { certified: self.certified_key() });
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);
        Ok(Arc::new(config))
    }

    /// A **mutual-TLS client** config: presents this TPM identity and accepts a
    /// server only if its certificate equals `pinned_server`.
    pub fn client_config(
        &self,
        pinned_server: CertificateDer<'static>,
    ) -> anyhow::Result<Arc<rustls::ClientConfig>> {
        install_provider();
        let verifier = Arc::new(PinnedServerAuth::new(vec![pinned_server]));
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(verify::SingleClientCert {
                certified: self.certified_key(),
            }));
        Ok(Arc::new(config))
    }
}

/// Install the process-default rustls crypto provider (idempotent).
fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// --- rcgen remote signer: the TPM signs the certificate itself ---

struct TpmRemoteKeyPair {
    backend: Arc<dyn TpmBackend>,
    handle: KeyHandle,
    /// Uncompressed SEC1 point `0x04 || X || Y` (rcgen's `public_key_raw`).
    point: Vec<u8>,
}

impl rcgen::RemoteKeyPair for TpmRemoteKeyPair {
    fn public_key(&self) -> &[u8] {
        &self.point
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let tpmt = self
            .backend
            .sign(&self.handle, msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        ecdsa_tpmt_to_der(&tpmt).ok_or(rcgen::Error::RemoteKeyError)
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

// --- rustls signing key: the TPM signs each handshake ---

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
        // `backend.sign` hashes (SHA-256, matching ECDSA_NISTP256_SHA256) and
        // signs inside the TPM, returning a TPMT_SIGNATURE. TLS wants DER ECDSA.
        let tpmt = self
            .backend
            .sign(&self.handle, message)
            .map_err(|e| rustls::Error::General(format!("TPM signing failed: {e}")))?;
        ecdsa_tpmt_to_der(&tpmt).ok_or_else(|| {
            rustls::Error::General("TPM did not return a parseable ECDSA TPMT_SIGNATURE".into())
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// --- TPM2B_PUBLIC ECC-point parsing ---

/// Extract the uncompressed SEC1 point (`0x04 || X || Y`, 65 bytes for P-256)
/// from a marshaled `TPM2B_PUBLIC` of an ECC key (what `public_blob` returns).
pub fn parse_ecc_point(t2b: &[u8]) -> anyhow::Result<Vec<u8>> {
    const TPM_ALG_ECC: u16 = 0x0023;
    const TPM_ALG_NULL: u16 = 0x0010;
    let mut r = Reader { b: t2b, p: 0 };
    let _size = r.u16()?; // TPM2B size prefix
    if r.u16()? != TPM_ALG_ECC {
        anyhow::bail!("not an ECC TPM2B_PUBLIC");
    }
    let _name_alg = r.u16()?;
    let _obj_attrs = r.u32()?;
    let auth_len = r.u16()? as usize; // authPolicy TPM2B
    r.skip(auth_len)?;
    // TPMS_ECC_PARMS: symmetric, scheme, curveID, kdf.
    let sym = r.u16()?;
    if sym != TPM_ALG_NULL {
        r.u16()?; // keyBits
        r.u16()?; // mode
    }
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        r.u16()?; // scheme hashAlg (e.g. ECDSA + SHA256)
    }
    let _curve = r.u16()?;
    let kdf = r.u16()?;
    if kdf != TPM_ALG_NULL {
        r.u16()?; // kdf hashAlg
    }
    // unique: TPMS_ECC_POINT { x: TPM2B, y: TPM2B }.
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    push_fixed(&mut point, x, 32);
    push_fixed(&mut point, y, 32);
    Ok(point)
}

/// Left-pad (or pass through) a coordinate to `width` bytes.
fn push_fixed(out: &mut Vec<u8>, coord: &[u8], width: usize) {
    if coord.len() < width {
        out.extend(std::iter::repeat_n(0u8, width - coord.len()));
    }
    out.extend_from_slice(coord);
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        let end = self.p.checked_add(n).filter(|&e| e <= self.b.len());
        let end = end.ok_or_else(|| anyhow::anyhow!("TPM2B_PUBLIC truncated"))?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u16(&mut self) -> anyhow::Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> anyhow::Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn skip(&mut self, n: usize) -> anyhow::Result<()> {
        self.take(n).map(|_| ())
    }
    fn tpm2b(&mut self) -> anyhow::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

// --- TPMT_SIGNATURE (ECDSA) → DER ECDSA-Sig-Value ---

fn ecdsa_tpmt_to_der(sig: &[u8]) -> Option<Vec<u8>> {
    const TPM_ALG_ECDSA: u16 = 0x0018;
    if sig.len() < 6 || u16::from_be_bytes([sig[0], sig[1]]) != TPM_ALG_ECDSA {
        return None;
    }
    // sig[2..4] = hashAlg (unused).
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
    Some(der_ecdsa_sig(r, &sig[s_start..s_end]))
}

fn der_ecdsa_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = der_uint(r);
    body.extend(der_uint(s));
    let mut out = vec![0x30u8, body.len() as u8];
    out.extend(body);
    out
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ecc_point_matches_the_vtpm_public_layout() {
        // A TPM2B_PUBLIC shaped exactly like the vTPM's ECC key (ECC, SHA256,
        // attrs, authPolicy, sym=NULL, scheme=ECDSA+SHA256, P256, kdf=NULL,
        // unique{x,y}).
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let mut tpmt = Vec::new();
        tpmt.extend_from_slice(&0x0023u16.to_be_bytes()); // ECC
        tpmt.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA256
        tpmt.extend_from_slice(&0x0003_0472u32.to_be_bytes()); // attrs
        tpmt.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
        tpmt.extend_from_slice(&0x0010u16.to_be_bytes()); // sym NULL
        tpmt.extend_from_slice(&0x0018u16.to_be_bytes()); // scheme ECDSA
        tpmt.extend_from_slice(&0x000Bu16.to_be_bytes()); // scheme hashAlg SHA256
        tpmt.extend_from_slice(&0x0003u16.to_be_bytes()); // curve P256
        tpmt.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
        tpmt.extend_from_slice(&32u16.to_be_bytes());
        tpmt.extend_from_slice(&x);
        tpmt.extend_from_slice(&32u16.to_be_bytes());
        tpmt.extend_from_slice(&y);
        // TPM2B_PUBLIC = size || TPMT_PUBLIC.
        let mut t2b = (tpmt.len() as u16).to_be_bytes().to_vec();
        t2b.extend_from_slice(&tpmt);

        let point = parse_ecc_point(&t2b).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..33], &x);
        assert_eq!(&point[33..65], &y);
    }

    #[test]
    fn ecdsa_tpmt_to_der_round_trips_a_signature() {
        // TPMT_SIGNATURE: ECDSA, SHA256, R(2B len+bytes), S(2B len+bytes).
        let mut sig = Vec::new();
        sig.extend_from_slice(&0x0018u16.to_be_bytes());
        sig.extend_from_slice(&0x000Bu16.to_be_bytes());
        sig.extend_from_slice(&3u16.to_be_bytes());
        sig.extend_from_slice(&[0x01, 0x02, 0x03]);
        sig.extend_from_slice(&3u16.to_be_bytes());
        sig.extend_from_slice(&[0x04, 0x05, 0x06]);
        let der = ecdsa_tpmt_to_der(&sig).unwrap();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert!(der.len() >= 8);
    }
}
