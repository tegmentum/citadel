//! `vsss-rs`-backed Shamir sharing (feature `shamir-vsss`) — the alternative,
//! reviewed backend to the default `sharks`, selected via [`super::SecretSharing`].
//! Uses vsss-rs's GF(2^8) byte-array split/combine. `vsss-rs` also supports
//! *verifiable* secret sharing (Feldman/Pedersen) over the same crate, the reason
//! to prefer it when shares must be checkable.

use rand::rngs::OsRng;
use vsss_rs::Gf256;

use super::{SecretSharing, Share};

/// Shamir secret sharing over GF(2^8) via the `vsss-rs` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct VsssSharing;

impl SecretSharing for VsssSharing {
    fn split(&self, secret: &[u8], k: u8, n: u8) -> Vec<Share> {
        assert!(k >= 1 && k <= n && n >= 1, "require 1 <= k <= n");
        Gf256::split_array(k as usize, n as usize, secret, OsRng)
            .expect("vsss split")
            .into_iter()
            .map(|bytes| Share { bytes })
            .collect()
    }

    fn combine(&self, shares: &[Share]) -> Vec<u8> {
        let raw: Vec<Vec<u8>> = shares.iter().map(|s| s.bytes.clone()).collect();
        Gf256::combine_array(&raw).unwrap_or_default()
    }
}
