//! Mesh message signing (Ed25519).
//!
//! Every gossip envelope, attestation record, and vote in the mesh is
//! signed so a recipient can bind it to a sender identity — "make
//! deception require distributed collusion" starts with every message
//! being attributable. This is distinct from the *attestation* identity
//! (the TPM-backed AK that signs quotes); this is the per-node **evidence
//! identity** used for mesh-protocol messages (design §6.1).
//!
//! Keys are derived deterministically from a 32-byte seed so the in-process
//! harness and tests are reproducible; in production the seed is generated
//! from a CSPRNG and ideally TPM-sealed (open question §21.2).

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A node's mesh signing keypair (private). Not serializable by design —
/// only the public half and signatures cross the wire.
#[derive(Clone)]
pub struct MeshKeypair {
    signing: SigningKey,
}

impl MeshKeypair {
    /// Derive a keypair from a 32-byte seed (deterministic).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        MeshKeypair {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The public verifying key to publish to peers.
    pub fn public(&self) -> MeshPublicKey {
        MeshPublicKey(self.signing.verifying_key().to_bytes())
    }

    /// Sign a canonical message.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.signing.sign(msg).to_bytes())
    }
}

impl std::fmt::Debug for MeshKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshKeypair({})", self.public().fingerprint_short())
    }
}

/// A node's mesh public key (Ed25519). Serialized as hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MeshPublicKey(pub [u8; 32]);

impl MeshPublicKey {
    /// Verify `sig` over `msg`. `false` on any malformed key/signature.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let dsig = DalekSig::from_bytes(&sig.0);
        vk.verify(msg, &dsig).is_ok()
    }

    /// BLAKE3 fingerprint of the public key — the `ak_fingerprint` input to
    /// [`crate::id::NodeId::derive`] when this key stands in for the
    /// attestation identity (Phase 0; Phase 1 uses the real AK public).
    pub fn fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }

    pub fn fingerprint_short(&self) -> String {
        self.fingerprint()[..6].iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(MeshPublicKey(out))
    }
}

impl std::fmt::Debug for MeshPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshPublicKey({})", self.fingerprint_short())
    }
}

impl Serialize for MeshPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for MeshPublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MeshPublicKey::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid public key hex"))
    }
}

/// An Ed25519 signature (64 bytes). Serialized as hex.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// A zero signature placeholder for messages not yet signed.
    pub fn zero() -> Self {
        Signature([0u8; 64])
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 128 {
            return None;
        }
        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Signature(out))
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}…)", &self.to_hex()[..12])
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Signature::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid signature hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper_detection() {
        let kp = MeshKeypair::from_seed([7u8; 32]);
        let pk = kp.public();
        let msg = b"gossip-envelope-bytes";
        let sig = kp.sign(msg);
        assert!(pk.verify(msg, &sig), "valid signature verifies");
        assert!(!pk.verify(b"tampered", &sig), "tampered message fails");

        let other = MeshKeypair::from_seed([8u8; 32]).public();
        assert!(!other.verify(msg, &sig), "another key does not verify");
    }

    #[test]
    fn seed_is_deterministic() {
        let a = MeshKeypair::from_seed([1u8; 32]).public();
        let b = MeshKeypair::from_seed([1u8; 32]).public();
        assert_eq!(a, b);
    }

    #[test]
    fn public_key_and_signature_hex_roundtrip() {
        let kp = MeshKeypair::from_seed([3u8; 32]);
        let pk = kp.public();
        assert_eq!(MeshPublicKey::from_hex(&pk.to_hex()), Some(pk));
        let sig = kp.sign(b"x");
        assert_eq!(Signature::from_hex(&sig.to_hex()), Some(sig));
    }
}
