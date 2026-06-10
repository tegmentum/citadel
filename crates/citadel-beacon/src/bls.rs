//! P4 (MB hardening) — an **unbiasable** threshold-BLS beacon.
//!
//! The FROST/Schnorr beacon (MB1) is unpredictable + single-node-unbiasable, but
//! a *colluding* signing quorum could grind nonces to bias the output. A
//! **threshold-BLS** signature has **no nonce** — it is deterministic and *unique
//! per message* — so the beacon value is a fixed function of `(round ‖ prev)` and
//! cannot be ground by any quorum: a true unique-per-input VRF. Any threshold of
//! holders, in any combination, produces the *identical* signature.
//!
//! Behind the `bls` feature (pulls a BLS12-381 pairing dependency).

use blsttc::{PublicKeySet, SecretKeyShare, Signature};
use serde::{Deserialize, Serialize};

pub use crate::{message, GENESIS_PREV};

/// Generate a `threshold`-of-`n` BLS beacon group (`threshold`+1 shares are
/// needed to produce a beacon). Returns the group public key set + per-holder
/// secret key shares.
pub fn keygen(threshold: usize, n: usize) -> (PublicKeySet, Vec<SecretKeyShare>) {
    let sks = blsttc::SecretKeySet::random(threshold, &mut rand::thread_rng());
    let pks = sks.public_keys();
    let shares = (1..=n).map(|i| sks.secret_key_share(i)).collect();
    (pks, shares)
}

/// One BLS beacon round: round number, the predecessor it commits to, and the
/// combined threshold-BLS signature over `message(round, prev)` (serialized).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlsBeaconRound {
    pub round: u64,
    pub prev: [u8; 32],
    pub signature: Vec<u8>,
}

impl BlsBeaconRound {
    /// Produce a round: a threshold of holders sign and the shares combine into
    /// the (unique) group signature. `signers` are `(index, share)` for ≥
    /// threshold+1 holders, where `index` matches the `keygen` order (1-based).
    pub fn produce(
        round: u64,
        prev: [u8; 32],
        public: &PublicKeySet,
        signers: &[(usize, &SecretKeyShare)],
    ) -> anyhow::Result<Self> {
        let msg = message(round, &prev);
        let sig_shares: Vec<(usize, _)> = signers.iter().map(|(i, s)| (*i, s.sign(&msg))).collect();
        let signature = public
            .combine_signatures(sig_shares.iter().map(|(i, s)| (*i, s)))
            .map_err(|e| anyhow::anyhow!("combine BLS shares: {e}"))?;
        Ok(BlsBeaconRound {
            round,
            prev,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Verify the round against the group public key.
    pub fn verify(&self, public: &PublicKeySet) -> bool {
        let bytes: [u8; 96] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        match Signature::from_bytes(bytes) {
            Ok(sig) => public
                .public_key()
                .verify(&sig, message(self.round, &self.prev)),
            Err(_) => false,
        }
    }

    /// The round's random output — `BLAKE3` of the (deterministic) signature.
    pub fn value(&self) -> [u8; 32] {
        *blake3::hash(&self.signature).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_beacon_is_deterministic_and_unbiasable() {
        // 2-of-4 (threshold degree 2 → 3 shares combine).
        let (public, shares) = keygen(2, 4);

        // Produce a round with shares {1,2,3}.
        let r_a = BlsBeaconRound::produce(
            0,
            GENESIS_PREV,
            &public,
            &[(1, &shares[0]), (2, &shares[1]), (3, &shares[2])],
        )
        .unwrap();
        assert!(r_a.verify(&public));

        // Produce the SAME round with a DIFFERENT quorum {2,3,4}.
        let r_b = BlsBeaconRound::produce(
            0,
            GENESIS_PREV,
            &public,
            &[(2, &shares[1]), (3, &shares[2]), (4, &shares[3])],
        )
        .unwrap();
        assert!(r_b.verify(&public));

        // Unbiasable: the signature (and value) is IDENTICAL regardless of which
        // quorum signed — there is no nonce to grind (unlike FROST, where two
        // productions differ).
        assert_eq!(
            r_a.signature, r_b.signature,
            "BLS threshold sig is unique per message"
        );
        assert_eq!(r_a.value(), r_b.value());

        // A different round yields a different value; tampering fails verify.
        let r1 = BlsBeaconRound::produce(
            1,
            r_a.value(),
            &public,
            &[(1, &shares[0]), (2, &shares[1]), (3, &shares[2])],
        )
        .unwrap();
        assert_ne!(r1.value(), r_a.value());
        let mut bad = r_a.clone();
        bad.round = 9;
        assert!(!bad.verify(&public));
    }
}
