//! Shamir `k`-of-`n` secret sharing over GF(2^8) — the threshold-custody core of
//! Mesh-Sealed Secrets (MSS6). A secret is split into `n` shares such that any
//! `k` reconstruct it and any `k-1` reveal nothing; combined with sealing each
//! share to a distinct holder's TPM, **no single node ever holds the whole
//! secret at rest** (design call C1, distributed-HSM §16).
//!
//! Reconstruction reassembles the secret in the reconstructor's memory — fine
//! for secrets that are *consumed* (DB passwords, API tokens). For keys that must
//! never be reassembled even transiently (CA / JWT signing keys), the further
//! track is **threshold signing** (e.g. FROST), where `k` parties produce a
//! signature without ever forming the key — noted in `mss-roadmap.md` as MSS6b.
//!
//! GF(2^8) uses the AES reducing polynomial (0x11b); this is a deliberately
//! small, auditable implementation. A production deployment should use a reviewed
//! threshold-crypto library.

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// One share: its x-coordinate (1..=n, never 0) and the share byte for each byte
/// of the secret (each secret byte is split by an independent polynomial).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    pub x: u8,
    pub ys: Vec<u8>,
}

/// GF(2^8) multiply (carry-less, reduced by 0x11b).
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// GF(2^8) multiplicative inverse: `a^254` (since `a^255 = 1` for `a != 0`).
fn ginv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gmul(result, base);
        }
        base = gmul(base, base);
        exp >>= 1;
    }
    result
}

/// Split `secret` into `n` shares with reconstruction threshold `k`. Panics if
/// `k == 0`, `k > n`, or `n == 0` (a programming error, not a runtime input).
pub fn split(secret: &[u8], k: u8, n: u8) -> Vec<Share> {
    assert!(k >= 1 && k <= n && n >= 1, "require 1 <= k <= n");
    let mut rng = rand::rngs::OsRng;
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            ys: Vec::with_capacity(secret.len()),
        })
        .collect();
    for &byte in secret {
        // Polynomial: coeffs[0] = the secret byte, the rest random (degree k-1).
        let mut coeffs = vec![byte];
        for _ in 1..k {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            coeffs.push(b[0]);
        }
        for s in &mut shares {
            // Horner evaluation of the polynomial at x = s.x.
            let mut acc = 0u8;
            for &c in coeffs.iter().rev() {
                acc = gmul(acc, s.x) ^ c;
            }
            s.ys.push(acc);
        }
    }
    shares
}

/// Reconstruct the secret from shares by Lagrange interpolation at `x = 0`. With
/// fewer than the threshold (or with mismatched shares) the result is a different
/// value, not the secret — Shamir reveals nothing below `k`.
pub fn combine(shares: &[Share]) -> Vec<u8> {
    if shares.is_empty() {
        return Vec::new();
    }
    let len = shares[0].ys.len();
    let mut out = vec![0u8; len];
    for (j, byte) in out.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, si) in shares.iter().enumerate() {
            // Lagrange basis L_i(0) = prod_{m != i} x_m / (x_m - x_i); in GF(2)
            // subtraction is XOR.
            let (mut num, mut den) = (1u8, 1u8);
            for (m, sm) in shares.iter().enumerate() {
                if m == i {
                    continue;
                }
                num = gmul(num, sm.x);
                den = gmul(den, sm.x ^ si.x);
            }
            let lagrange = gmul(num, ginv(den));
            acc ^= gmul(si.ys[j], lagrange);
        }
        *byte = acc;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_k_of_n_reconstructs_the_secret() {
        let secret = b"db-prod-password-32-bytes-long!!";
        let shares = split(secret, 3, 5);
        assert_eq!(shares.len(), 5);
        // Several distinct 3-subsets all recover the same secret.
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
        // Any 2 shares (k-1) interpolate a different value — not the secret.
        assert_ne!(combine(&shares[0..2]), secret.to_vec());
        assert_ne!(combine(&shares[2..4]), secret.to_vec());
    }

    #[test]
    fn two_of_two_and_single_share_edges() {
        let secret = b"abc";
        let s = split(secret, 2, 2);
        assert_eq!(combine(&s), secret);
        // A single share of a 2-of-2 is just one point — not the secret.
        assert_ne!(combine(&s[0..1]), secret.to_vec());
    }
}
