//! Shamir `k`-of-`n` secret sharing — the threshold-custody core of MSS6. A
//! secret is split into `n` shares such that any `k` reconstruct it and any
//! `k-1` reveal nothing; combined with sealing each share to a distinct holder's
//! TPM, **no single node ever holds the whole secret at rest** (design call C1).
//!
//! The sharing backend is **pluggable** via [`SecretSharing`]: [`SharksSharing`]
//! (the reviewed `sharks` crate, default, always available) or [`VsssSharing`]
//! (the `vsss-rs` crate, enabled with the `shamir-vsss` feature). A deployment
//! picks one; `Share` is an opaque byte wrapper, so split + combine must use the
//! same backend. Reconstruction reassembles the secret in memory (fine for
//! *consumed* secrets); keys that must never be reassembled use threshold signing
//! (`tsig`, MSS6b).

use serde::{Deserialize, Serialize};

/// One opaque Shamir share — the backend's wire encoding. Sealed to a holder's
/// TPM and exchanged as bytes; only meaningful to the backend that produced it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    pub bytes: Vec<u8>,
}

/// A pluggable Shamir secret-sharing backend.
pub trait SecretSharing: Send + Sync {
    /// Split `secret` into `n` shares with reconstruction threshold `k`.
    fn split(&self, secret: &[u8], k: u8, n: u8) -> Vec<Share>;
    /// Reconstruct from shares (≥ `k` → the secret; fewer → a different value).
    fn combine(&self, shares: &[Share]) -> Vec<u8>;
}

/// The default backend: Shamir over GF(2^8) via the reviewed `sharks` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct SharksSharing;

impl SecretSharing for SharksSharing {
    fn split(&self, secret: &[u8], k: u8, n: u8) -> Vec<Share> {
        assert!(k >= 1 && k <= n && n >= 1, "require 1 <= k <= n");
        sharks::Sharks(k)
            .dealer(secret)
            .take(n as usize)
            .map(|s| Share {
                bytes: Vec::from(&s),
            })
            .collect()
    }

    fn combine(&self, shares: &[Share]) -> Vec<u8> {
        let parsed: Vec<sharks::Share> = shares
            .iter()
            .filter_map(|s| sharks::Share::try_from(s.bytes.as_slice()).ok())
            .collect();
        if parsed.is_empty() {
            return Vec::new();
        }
        sharks::Sharks(parsed.len() as u8)
            .recover(parsed.iter())
            .unwrap_or_default()
    }
}

/// The default sharing backend ([`SharksSharing`]).
pub fn default_sharing() -> impl SecretSharing {
    SharksSharing
}

/// Split with the default backend ([`SharksSharing`]).
pub fn split(secret: &[u8], k: u8, n: u8) -> Vec<Share> {
    SharksSharing.split(secret, k, n)
}

/// Reconstruct with the default backend ([`SharksSharing`]).
pub fn combine(shares: &[Share]) -> Vec<u8> {
    SharksSharing.combine(shares)
}

#[cfg(feature = "shamir-vsss")]
mod vsss;
#[cfg(feature = "shamir-vsss")]
pub use vsss::VsssSharing;

#[cfg(test)]
mod tests {
    use super::*;

    fn cases(s: &impl SecretSharing) {
        let secret = b"db-prod-password-32-bytes-long!!";
        let shares = s.split(secret, 3, 5);
        assert_eq!(shares.len(), 5);
        for subset in [[0, 1, 2], [2, 3, 4], [0, 2, 4]] {
            let picked: Vec<Share> = subset.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(s.combine(&picked), secret, "subset {subset:?} recovers");
        }
        assert_ne!(
            s.combine(&shares[0..2]),
            secret.to_vec(),
            "k-1 reveals nothing"
        );
        let two = s.split(b"abc", 2, 2);
        assert_eq!(s.combine(&two), b"abc");
        assert_ne!(s.combine(&two[0..1]), b"abc".to_vec());
    }

    #[test]
    fn sharks_backend_round_trips() {
        cases(&SharksSharing);
    }

    #[cfg(feature = "shamir-vsss")]
    #[test]
    fn vsss_backend_round_trips() {
        cases(&VsssSharing);
    }
}
