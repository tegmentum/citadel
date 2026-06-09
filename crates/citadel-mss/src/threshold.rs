//! Shamir `k`-of-`n` secret sharing — the threshold-custody core of MSS6. A
//! secret is split into `n` shares such that any `k` reconstruct it and any
//! `k-1` reveal nothing; combined with sealing each share to a distinct holder's
//! TPM, **no single node ever holds the whole secret at rest** (design call C1).
//!
//! Backed by the reviewed `sharks` crate (Shamir over GF(2^8)) rather than a
//! hand-rolled field, per the production-hardening note. (Production should still
//! pin + review the chosen library; `vsss-rs` is the alternative when *verifiable*
//! secret sharing is needed.) Reconstruction reassembles the secret in memory —
//! fine for *consumed* secrets; keys that must never be reassembled use threshold
//! signing (`tsig`, MSS6b).

use serde::{Deserialize, Serialize};
use sharks::Sharks;

/// One opaque Shamir share (the `sharks` wire encoding: x-coordinate + the share
/// byte per secret byte). Sealed to a holder's TPM and exchanged as bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    pub bytes: Vec<u8>,
}

/// Split `secret` into `n` shares with reconstruction threshold `k`.
pub fn split(secret: &[u8], k: u8, n: u8) -> Vec<Share> {
    assert!(k >= 1 && k <= n && n >= 1, "require 1 <= k <= n");
    let sharks = Sharks(k);
    sharks
        .dealer(secret)
        .take(n as usize)
        .map(|s| Share {
            bytes: Vec::from(&s),
        })
        .collect()
}

/// Reconstruct the secret from shares. With at least the threshold it returns the
/// secret; with fewer (or mismatched shares) it returns a different value — Shamir
/// reveals nothing below `k`.
pub fn combine(shares: &[Share]) -> Vec<u8> {
    let parsed: Vec<sharks::Share> = shares
        .iter()
        .filter_map(|s| sharks::Share::try_from(s.bytes.as_slice()).ok())
        .collect();
    if parsed.is_empty() {
        return Vec::new();
    }
    // Interpolate over exactly the shares provided; `recover` reconstructs the
    // secret only when ≥ the deal threshold are present.
    Sharks(parsed.len() as u8)
        .recover(parsed.iter())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_k_of_n_reconstructs_the_secret() {
        let secret = b"db-prod-password-32-bytes-long!!";
        let shares = split(secret, 3, 5);
        assert_eq!(shares.len(), 5);
        for subset in [[0, 1, 2], [2, 3, 4], [0, 2, 4], [1, 3, 4]] {
            let picked: Vec<Share> = subset.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(
                combine(&picked),
                secret,
                "subset {subset:?} recovers the secret"
            );
        }
    }

    #[test]
    fn fewer_than_k_shares_do_not_reveal_the_secret() {
        let secret = b"top-secret-key-material";
        let shares = split(secret, 3, 5);
        assert_ne!(combine(&shares[0..2]), secret.to_vec());
    }

    #[test]
    fn two_of_two_and_single_share_edges() {
        let secret = b"abc";
        let s = split(secret, 2, 2);
        assert_eq!(combine(&s), secret);
        assert_ne!(combine(&s[0..1]), secret.to_vec());
    }
}
