//! Mesh and node identity.
//!
//! A node's canonical id is content-derived from the mesh it belongs to,
//! the enrollment epoch, a fingerprint of its attestation key, and an
//! assigned random salt (see the design doc §6.2):
//!
//! ```text
//! node_id = BLAKE3(mesh_id ‖ enrollment_epoch ‖ ak_fingerprint ‖ salt)
//! ```
//!
//! This keeps the id stable inside one mesh, bound to attested hardware,
//! not globally linkable by default, and re-enrollable under a new epoch.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Identifier of a mesh (a cluster-scoped trust domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshId(pub String);

impl MeshId {
    pub fn new(s: impl Into<String>) -> Self {
        MeshId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MeshId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic enrollment epoch. A node re-enrolling (new identity, same
/// hardware) advances its epoch, which changes its [`NodeId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

/// A node's canonical mesh id: a BLAKE3 digest. Serialized as lowercase
/// hex so it is stable across the wire and human-readable in logs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Derive the canonical node id (design §6.2).
    pub fn derive(mesh_id: &MeshId, epoch: Epoch, ak_fingerprint: &[u8], salt: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(mesh_id.as_str().as_bytes());
        h.update(b"\x00");
        h.update(&epoch.0.to_be_bytes());
        h.update(ak_fingerprint);
        h.update(b"\x00");
        h.update(salt);
        NodeId(*h.finalize().as_bytes())
    }

    /// Short hex prefix for display (first 8 bytes).
    pub fn short(&self) -> String {
        self.0[..8].iter().map(|b| format!("{:02x}", b)).collect()
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
        Some(NodeId(out))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        NodeId::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid NodeId hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_is_deterministic_and_epoch_sensitive() {
        let mesh = MeshId::new("prod-east-1");
        let ak = b"ak-fingerprint";
        let salt = b"salt-1234";
        let a = NodeId::derive(&mesh, Epoch(1), ak, salt);
        let a2 = NodeId::derive(&mesh, Epoch(1), ak, salt);
        let b = NodeId::derive(&mesh, Epoch(2), ak, salt);
        assert_eq!(a, a2, "same inputs derive the same id");
        assert_ne!(a, b, "a new epoch derives a new id");
    }

    #[test]
    fn node_id_separates_fields() {
        // Moving a byte across the epoch/ak boundary must change the id
        // (guards against trivial concatenation-collision).
        let mesh = MeshId::new("m");
        let x = NodeId::derive(&mesh, Epoch(0x0102030405060708), b"", b"");
        let y = NodeId::derive(&mesh, Epoch(0), b"\x01\x02\x03\x04\x05\x06\x07\x08", b"");
        assert_ne!(x, y);
    }

    #[test]
    fn node_id_hex_roundtrip() {
        let mesh = MeshId::new("m");
        let id = NodeId::derive(&mesh, Epoch(7), b"ak", b"s");
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(NodeId::from_hex(&hex), Some(id));
        assert_eq!(NodeId::from_hex("nope"), None);
    }

    #[test]
    fn node_id_serde_is_hex_string() {
        let mesh = MeshId::new("m");
        let id = NodeId::derive(&mesh, Epoch(1), b"ak", b"s");
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"') && json.len() == 66);
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
