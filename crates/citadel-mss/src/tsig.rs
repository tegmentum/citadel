//! Threshold **signing** (MSS6b) — FROST (Flexible Round-Optimized Schnorr
//! Threshold signatures, RFC 9591) over Ed25519, via the vetted
//! `frost-ed25519` crate. `k` holders jointly produce a valid Ed25519 signature
//! **without ever reconstructing the signing key** — the property MSS6's Shamir
//! mode can't give for keys that must never exist whole (CA / JWT signing keys).
//!
//! Trusted-dealer keygen forms the key once at deal time (then never again);
//! removing even that with distributed key generation (DKG) is the further
//! hardening. Signing here is orchestrated in-process for the prototype; the
//! mesh would carry the two FROST rounds over gossip, gated by a release
//! authorization (MSS1–3).

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use rand::rngs::OsRng;

pub use frost::keys::{KeyPackage, PublicKeyPackage};
pub use frost::Signature;

/// Trusted-dealer keygen: a `threshold`-of-`n` Ed25519 signing key, returned as
/// the group public package + one [`KeyPackage`] per holder (each to be sealed
/// to that holder's TPM). The full key is formed only here, never again.
pub fn keygen(threshold: u16, n: u16) -> anyhow::Result<(PublicKeyPackage, Vec<KeyPackage>)> {
    let (shares, public) = frost::keys::generate_with_dealer(
        n,
        threshold,
        frost::keys::IdentifierList::Default,
        OsRng,
    )?;
    let mut packages = Vec::with_capacity(shares.len());
    for (_id, share) in shares {
        packages.push(frost::keys::KeyPackage::try_from(share)?);
    }
    Ok((public, packages))
}

/// Produce a group signature from `packages` (≥ threshold holders' key packages)
/// over `message`, running both FROST rounds + aggregation. The signing key is
/// never reassembled. Fewer than the threshold cannot produce a verifying
/// signature.
pub fn sign(
    packages: &[KeyPackage],
    public: &PublicKeyPackage,
    message: &[u8],
) -> anyhow::Result<Signature> {
    let mut rng = OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for kp in packages {
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces.insert(*kp.identifier(), n);
        commitments.insert(*kp.identifier(), c);
    }
    let signing_package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for kp in packages {
        let share = frost::round2::sign(&signing_package, &nonces[kp.identifier()], kp)?;
        shares.insert(*kp.identifier(), share);
    }
    Ok(frost::aggregate(&signing_package, &shares, public)?)
}

/// Verify a group signature against the threshold key's group verifying key.
pub fn verify(public: &PublicKeyPackage, message: &[u8], sig: &Signature) -> bool {
    public.verifying_key().verify(message, sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_holders_sign_without_reconstructing_the_key() {
        let (public, packages) = keygen(3, 5).unwrap();
        let msg = b"issue-cert: cn=node-1";

        // Any 3 holders produce a valid group signature.
        let sig = sign(&packages[0..3], &public, msg).unwrap();
        assert!(verify(&public, msg, &sig));
        // A different message is not covered by it.
        assert!(!verify(&public, b"issue-cert: cn=attacker", &sig));

        // A different 3-subset also produces a valid signature (same group key).
        let sig2 = sign(
            &[
                packages[1].clone(),
                packages[3].clone(),
                packages[4].clone(),
            ],
            &public,
            msg,
        )
        .unwrap();
        assert!(verify(&public, msg, &sig2));
    }

    #[test]
    fn fewer_than_threshold_cannot_sign() {
        let (public, packages) = keygen(3, 5).unwrap();
        let msg = b"sign me";
        // 2 of a 3-threshold key cannot produce a verifying signature.
        let ok = sign(&packages[0..2], &public, msg)
            .map(|sig| verify(&public, msg, &sig))
            .unwrap_or(false);
        assert!(
            !ok,
            "below-threshold signing must not yield a valid signature"
        );
    }
}
