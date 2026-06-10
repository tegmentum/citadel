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

// -- MSS8a: generation-fenced shares + proactive reshare ---------------------

/// A Shamir share tagged with its committee **generation**. Cross-generation
/// shares never combine ([`combine_gen`]), so a refresh invalidates old shares
/// against the new generation and a returning evicted holder's stale share is
/// fenced out (MSS8 D4).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenShare {
    pub generation: u64,
    pub share: Share,
}

/// Combine generation-tagged shares — **only if they all carry one generation**
/// (≥ `k` of the same generation → the secret; a mixed generation, or fewer than
/// `k`, → `None`). Mixing a stale-generation (zombie) share into the current
/// generation is refused: this is the generation fence.
///
/// Note: `k` same-generation shares still reconstruct, so an attacker holding `k`
/// *old* shares of one generation can reconstruct — defended at deployment by
/// TPM-sealing each share to its holder + proactive deletion on eviction. The
/// fence here stops cross-generation combination (refresh + zombie-in-the-current-
/// committee).
pub fn combine_gen(shares: &[GenShare]) -> Option<Vec<u8>> {
    let generation = shares.first()?.generation;
    if !shares.iter().all(|s| s.generation == generation) {
        return None; // cross-generation: fenced
    }
    let raw: Vec<Share> = shares.iter().map(|s| s.share.clone()).collect();
    let secret = combine(&raw);
    (!secret.is_empty()).then_some(secret)
}

/// Reshare: from ≥ `k` current-generation shares, mint fresh shares for a new
/// committee of `new_n` at `next_gen`, on a **new** polynomial (refresh). `None`
/// if the inputs don't combine (mixed generation / fewer than `k`).
///
/// This transiently reconstructs the secret — consistent with custody's
/// reassemble-on-use model, and the reshare is quorum-gated like a release. The
/// fully-distributed, no-reassembly variant (PSS sub-sharing / FROST reshare) is
/// MSS8c.
pub fn reshare(current: &[GenShare], k: u8, new_n: u8, next_gen: u64) -> Option<Vec<GenShare>> {
    let secret = combine_gen(current)?;
    let fresh = split(&secret, k, new_n);
    Some(
        fresh
            .into_iter()
            .map(|share| GenShare {
                generation: next_gen,
                share,
            })
            .collect(),
    )
}

#[cfg(test)]
mod reshare_tests {
    use super::*;

    fn gen(secret: &[u8], k: u8, n: u8, g: u64) -> Vec<GenShare> {
        split(secret, k, n)
            .into_iter()
            .map(|share| GenShare {
                generation: g,
                share,
            })
            .collect()
    }

    #[test]
    fn reshare_keeps_the_secret_refreshes_shares_and_fences_generations() {
        let secret = b"cluster custody secret".to_vec();
        let g0 = gen(&secret, 3, 5, 0);
        assert_eq!(
            combine_gen(&g0[..3]),
            Some(secret.clone()),
            "gen-0 reconstructs"
        );

        // Reshare to a new gen-1 committee from 3 surviving gen-0 shares.
        let g1 = reshare(&g0[..3], 3, 5, 1).expect("reshare");
        assert!(g1.iter().all(|s| s.generation == 1));
        assert_eq!(
            combine_gen(&g1[..3]),
            Some(secret.clone()),
            "gen-1 reconstructs the SAME secret"
        );

        // Generation fence: a returning evicted holder's stale gen-0 share mixed
        // into the gen-1 committee is refused (it's on a different polynomial).
        let mut zombie_mix = g1[..2].to_vec();
        zombie_mix.push(g0[0].clone());
        assert_eq!(combine_gen(&zombie_mix), None, "cross-generation is fenced");

        // Fewer than k of one generation does not reveal the secret.
        assert_ne!(combine_gen(&g1[..2]), Some(secret.clone()));

        // A reshare can also rebalance to a different committee size (reshare-to-
        // available): gen-2 with n=4 from gen-1 survivors still yields the secret.
        let g2 = reshare(&g1[..3], 3, 4, 2).expect("reshare to a smaller committee");
        assert_eq!(g2.len(), 4);
        assert_eq!(combine_gen(&g2[..3]), Some(secret));
    }
}
