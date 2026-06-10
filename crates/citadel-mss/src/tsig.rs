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

/// Distributed key generation (DKG): the `threshold`-of-`n` key is built by the
/// participants running the three FROST DKG rounds, so **no party — not even a
/// dealer — ever holds the whole signing key**, even at generation time (the
/// hardening over [`keygen`]'s trusted dealer). Orchestrated in-process here; the
/// mesh would carry the rounds over gossip.
pub fn keygen_dkg(threshold: u16, n: u16) -> anyhow::Result<(PublicKeyPackage, Vec<KeyPackage>)> {
    use frost::keys::dkg;
    use frost::Identifier;
    let ids: Vec<Identifier> = (1..=n)
        .map(|i| Identifier::try_from(i).map_err(|e| anyhow::anyhow!("identifier: {e}")))
        .collect::<anyhow::Result<_>>()?;

    // Round 1: each participant commits; its package goes to all the others.
    let mut r1_secrets = BTreeMap::new();
    let mut r1_pkgs = BTreeMap::new();
    for id in &ids {
        let (secret, pkg) = dkg::part1(*id, n, threshold, OsRng)?;
        r1_secrets.insert(*id, secret);
        r1_pkgs.insert(*id, pkg);
    }
    let others_r1 = |me: &Identifier| -> BTreeMap<Identifier, dkg::round1::Package> {
        r1_pkgs
            .iter()
            .filter(|(j, _)| *j != me)
            .map(|(j, p)| (*j, p.clone()))
            .collect()
    };

    // Round 2: each participant produces a package addressed to each other.
    let mut r2_secrets = BTreeMap::new();
    let mut r2_by_sender: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>> =
        BTreeMap::new();
    for id in &ids {
        let (secret, pkgs) = dkg::part2(r1_secrets.remove(id).unwrap(), &others_r1(id))?;
        r2_secrets.insert(*id, secret);
        r2_by_sender.insert(*id, pkgs);
    }

    // Round 3: each participant derives its key package + the shared group key.
    let mut key_packages = Vec::with_capacity(ids.len());
    let mut public = None;
    for id in &ids {
        let r2_for_me: BTreeMap<Identifier, dkg::round2::Package> = r2_by_sender
            .iter()
            .filter(|(j, _)| *j != id)
            .filter_map(|(j, pkgs)| pkgs.get(id).map(|p| (*j, p.clone())))
            .collect();
        let (kp, pubkey) = dkg::part3(&r2_secrets[id], &others_r1(id), &r2_for_me)?;
        key_packages.push(kp);
        public = Some(pubkey);
    }
    Ok((public.expect("n >= 1"), key_packages))
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
    fn dkg_generates_a_signable_key_with_no_dealer() {
        // The key is built by the participants (no trusted dealer ever holds it).
        let (public, packages) = keygen_dkg(3, 5).unwrap();
        assert_eq!(packages.len(), 5);
        let msg = b"dkg-signed";
        let sig = sign(&packages[0..3], &public, msg).unwrap();
        assert!(verify(&public, msg, &sig));
        // A different 3-subset signs under the same group key.
        let sig2 = sign(
            &[
                packages[1].clone(),
                packages[2].clone(),
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

// -- MSS8c: FROST reshare (same group key, no reassembly) ---------------------

/// Refresh (reshare) a FROST committee, **keeping the same group public key** and
/// **never reconstructing the private key** (MSS8c — the signing-committee analog
/// of the custody reshare, for the signing / beacon / CA committees). The
/// refreshing members re-randomize their shares onto a fresh polynomial via the
/// Trusted-Dealer refresh; the member set may **drop** holders (down to the
/// threshold), which evicts a departed/zombie holder (its un-refreshed share is on
/// the old polynomial and can't co-sign with the refreshed set). `threshold` must
/// equal the group's original threshold (refresh can't lower it). Adding a
/// brand-new identity uses the DKG refresh (`refresh_dkg_*`), a follow-on.
///
/// Returns the refreshed public package (same verifying key) + the new key
/// packages, in the order of `current_packages`.
pub fn refresh(
    public: &PublicKeyPackage,
    current_packages: &[KeyPackage],
    threshold: u16,
) -> anyhow::Result<(PublicKeyPackage, Vec<KeyPackage>)> {
    use frost::keys::refresh::{compute_refreshing_shares, refresh_share};
    let max = current_packages.len() as u16;
    let identifiers: Vec<frost::Identifier> =
        current_packages.iter().map(|p| *p.identifier()).collect();
    let (refreshing, new_public) = compute_refreshing_shares::<frost::Ed25519Sha512, _>(
        public.clone(),
        max,
        threshold,
        &identifiers,
        &mut OsRng,
    )?;
    let new_packages = current_packages
        .iter()
        .zip(refreshing)
        .map(|(pkg, rs)| refresh_share::<frost::Ed25519Sha512>(rs, pkg))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((new_public, new_packages))
}

#[cfg(test)]
mod refresh_tests {
    use super::*;

    #[test]
    fn refresh_keeps_the_group_key_without_reassembly_and_evicts_on_drop() {
        let (public, packages) = keygen(3, 5).unwrap();
        let msg = b"cluster release v2";
        assert!(verify(
            &public,
            msg,
            &sign(&packages[0..3], &public, msg).unwrap()
        ));

        // Refresh the whole committee → SAME group key, new shares, no reassembly.
        let (new_public, new_packages) = refresh(&public, &packages, 3).unwrap();
        assert_eq!(
            new_public.verifying_key(),
            public.verifying_key(),
            "refresh preserves the group public key"
        );
        let sig = sign(&new_packages[0..3], &new_public, msg).unwrap();
        assert!(
            verify(&public, msg, &sig),
            "refreshed committee signs under the SAME key"
        );

        // Drop a holder: refresh among 4 survivors (threshold still 3, same key) —
        // the dropped holder is evicted.
        let (sub_public, sub_packages) = refresh(&public, &packages[0..4], 3).unwrap();
        assert_eq!(sub_public.verifying_key(), public.verifying_key());
        assert_eq!(sub_packages.len(), 4);
        assert!(verify(
            &public,
            msg,
            &sign(&sub_packages[0..3], &sub_public, msg).unwrap()
        ));

        // Fence: a stale (pre-refresh) share can't co-sign with refreshed shares.
        let mut mixed = new_packages[0..2].to_vec();
        mixed.push(packages[4].clone());
        let mixed = sign(&mixed, &new_public, msg);
        assert!(
            mixed.is_err() || !verify(&new_public, msg, &mixed.unwrap()),
            "old + refreshed shares cannot co-sign"
        );
    }
}
