//! # citadel-caps (CAP1) — continuously-earned capabilities
//!
//! MSS gates *secrets*; SPIFFE gates *identity*. This is the unifying primitive:
//! gate **any privileged action** on mesh authority. A capability is a signed,
//! **attenuable** token (macaroon/biscuit-style) — a holder may delegate a
//! *narrower* capability (shorter scope, tighter expiry, bound to a holder) but
//! never a broader one (CAP-C2). It carries a **lease** (deny-at-renewal, CAP-C3)
//! and a **beacon round** for freshness (CAP-C4), so a replayed token expires by
//! round, not just by clock.
//!
//! CAP1 is the pure token core: mint, attenuate (only-narrows), verify the
//! attenuation chain, and authorize an action. The quorum *issuance* over the
//! release protocol is CAP2 — there the `issuer` becomes the mesh's authority
//! (a single key here models that role; cf. MSS S0's single release authority,
//! distributed in MSS6).

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};
use citadel_mesh::NodeId;
use serde::{Deserialize, Serialize};

/// A narrowing predicate. A caveat can only *restrict* a capability.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Caveat {
    /// Valid only while the current beacon round ≤ N (a freshness/expiry bound).
    ExpiresAtRound(u64),
    /// Narrows the scope to this prefix — only valid if it *extends* the current
    /// scope (you can specialise `db:write` to `db:write:table-x`, never broaden).
    ScopePrefix(String),
    /// Binds the capability to a specific holder node.
    BoundToHolder(NodeId),
}

/// The base capability the mesh authority mints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    /// The privilege, as a hierarchical scope (e.g. `deploy:prod`, `db:write:prod`).
    pub scope: String,
    /// The node the capability is issued to.
    pub holder: NodeId,
    /// The beacon round at issuance (freshness anchor, MB).
    pub beacon_round: u64,
    /// Lease lifetime in beacon rounds (renewal re-runs the mesh vote — CAP-C3).
    pub lease_ticks: u64,
}

/// One attenuation link: added (narrowing) caveats, the delegate it's narrowed
/// to, and the previous holder's signature over the chain so far.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    pub caveats: Vec<Caveat>,
    pub delegate: MeshPublicKey,
    pub sig: Signature,
}

/// A capability token: the base capability signed by the issuer, plus an
/// attenuation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub capability: Capability,
    pub issuer: MeshPublicKey,
    pub root_sig: Signature,
    pub links: Vec<Link>,
}

/// The effective (narrowed) capability after applying every verified caveat.
#[derive(Clone, Debug)]
pub struct Effective {
    pub scope: String,
    pub beacon_round: u64,
    pub lease_ticks: u64,
    pub expires_round: Option<u64>,
    pub bound_holder: Option<NodeId>,
}

fn cap_bytes(c: &Capability) -> Vec<u8> {
    serde_json::to_vec(c).expect("serializable")
}

fn link_signing_bytes(
    cap: &Capability,
    prior: &[Link],
    caveats: &[Caveat],
    delegate: &MeshPublicKey,
) -> Vec<u8> {
    serde_json::to_vec(&("citadel-cap-link", cap_bytes(cap), prior, caveats, delegate))
        .expect("serializable")
}

/// Mint a capability: the issuer (the mesh authority) signs the base capability.
pub fn mint(issuer: &MeshKeypair, capability: Capability) -> CapabilityToken {
    let root_sig = issuer.sign(&cap_bytes(&capability));
    CapabilityToken {
        capability,
        issuer: issuer.public(),
        root_sig,
        links: vec![],
    }
}

/// Attenuate (delegate a *narrower* token): the current holder signs an appended
/// link adding caveats and a delegate. `holder` must be the token's current
/// effective holder (the issuer, or the previous link's delegate) — `verify`
/// enforces it.
pub fn attenuate(
    token: &CapabilityToken,
    holder: &MeshKeypair,
    caveats: Vec<Caveat>,
    delegate: MeshPublicKey,
) -> CapabilityToken {
    let msg = link_signing_bytes(&token.capability, &token.links, &caveats, &delegate);
    let sig = holder.sign(&msg);
    let mut t = token.clone();
    t.links.push(Link {
        caveats,
        delegate,
        sig,
    });
    t
}

/// Verify the whole token against the minting authority and reduce it to its
/// effective (narrowed) capability. Returns `None` if any signature is invalid or
/// an attenuation tries to *broaden* (a scope caveat that doesn't extend).
pub fn verify(token: &CapabilityToken, issuer_pub: &MeshPublicKey) -> Option<Effective> {
    if &token.issuer != issuer_pub
        || !issuer_pub.verify(&cap_bytes(&token.capability), &token.root_sig)
    {
        return None;
    }
    let mut scope = token.capability.scope.clone();
    let mut expires: Option<u64> = None;
    let mut bound = Some(token.capability.holder);
    let mut current_signer = *issuer_pub;

    for (i, link) in token.links.iter().enumerate() {
        let msg = link_signing_bytes(
            &token.capability,
            &token.links[..i],
            &link.caveats,
            &link.delegate,
        );
        if !current_signer.verify(&msg, &link.sig) {
            return None;
        }
        for cav in &link.caveats {
            match cav {
                Caveat::ScopePrefix(p) => {
                    // Only narrows: the new scope must extend the current one.
                    if !p.starts_with(&scope) {
                        return None;
                    }
                    scope = p.clone();
                }
                Caveat::ExpiresAtRound(n) => {
                    expires = Some(expires.map_or(*n, |e| e.min(*n)));
                }
                Caveat::BoundToHolder(h) => bound = Some(*h),
            }
        }
        current_signer = link.delegate;
    }
    Some(Effective {
        scope,
        beacon_round: token.capability.beacon_round,
        lease_ticks: token.capability.lease_ticks,
        expires_round: expires,
        bound_holder: bound,
    })
}

/// Does this effective capability authorize `action_scope` at `current_round`
/// for `requesting_holder`? Checks scope, lease freshness (beacon round), any
/// expiry caveat, and the holder binding.
pub fn authorizes(
    eff: &Effective,
    action_scope: &str,
    current_round: u64,
    requesting_holder: &NodeId,
) -> bool {
    if !action_scope.starts_with(&eff.scope) {
        return false; // out of (narrowed) scope
    }
    if current_round.saturating_sub(eff.beacon_round) > eff.lease_ticks {
        return false; // lease expired (deny-at-renewal)
    }
    if let Some(e) = eff.expires_round {
        if current_round > e {
            return false; // explicit expiry caveat
        }
    }
    if let Some(h) = eff.bound_holder {
        if h != *requesting_holder {
            return false; // bound to a different holder
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([n; 32])
    }
    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn base() -> (MeshKeypair, CapabilityToken) {
        let authority = kp(1);
        let cap = Capability {
            scope: "db:write".to_string(),
            holder: node(7),
            beacon_round: 100,
            lease_ticks: 10,
        };
        let token = mint(&authority, cap);
        (authority, token)
    }

    #[test]
    fn mint_verify_and_authorize_within_lease_and_scope() {
        let (authority, token) = base();
        let eff = verify(&token, &authority.public()).expect("valid token");
        // In-scope action within the lease window is authorized.
        assert!(authorizes(&eff, "db:write:table-x", 105, &node(7)));
        // Out of scope is refused.
        assert!(!authorizes(&eff, "db:read", 105, &node(7)));
        // Past the lease (round 100 + 10) it is refused (deny-at-renewal).
        assert!(!authorizes(&eff, "db:write:table-x", 120, &node(7)));
    }

    #[test]
    fn attenuation_only_narrows() {
        let (authority, token) = base();
        // The holder delegates a narrower token: scope db:write -> db:write:table-x,
        // tighter expiry, to a delegate key.
        let delegate = kp(9);
        let narrowed = attenuate(
            &token,
            &kp(1), // the issuer is the first holder (mint goes to the authority's chain root)
            vec![
                Caveat::ScopePrefix("db:write:table-x".to_string()),
                Caveat::ExpiresAtRound(108),
            ],
            delegate.public(),
        );
        let eff = verify(&narrowed, &authority.public()).expect("narrowed token verifies");
        assert_eq!(eff.scope, "db:write:table-x");
        // Now authorizes only the narrowed scope, and only before the tighter expiry.
        assert!(authorizes(&eff, "db:write:table-x:row1", 105, &node(7)));
        assert!(
            !authorizes(&eff, "db:write:table-y", 105, &node(7)),
            "narrowed away"
        );
        assert!(
            !authorizes(&eff, "db:write:table-x", 109, &node(7)),
            "expiry caveat"
        );

        // A broadening attenuation (scope shorter than the base) is rejected.
        let broaden = attenuate(
            &token,
            &kp(1),
            vec![Caveat::ScopePrefix("db".to_string())],
            delegate.public(),
        );
        assert!(
            verify(&broaden, &authority.public()).is_none(),
            "cannot broaden"
        );
    }

    #[test]
    fn tamper_and_wrong_signer_are_rejected() {
        let (authority, token) = base();
        // Tampering with the capability breaks the root signature.
        let mut tampered = token.clone();
        tampered.capability.scope = "root:everything".to_string();
        assert!(verify(&tampered, &authority.public()).is_none());

        // A link signed by the wrong key (not the current holder) is rejected.
        let impostor = kp(42);
        let forged = attenuate(
            &token,
            &impostor,
            vec![Caveat::ExpiresAtRound(105)],
            kp(9).public(),
        );
        assert!(
            verify(&forged, &authority.public()).is_none(),
            "link must be signed by the current holder"
        );
    }

    #[test]
    fn holder_binding_caveat() {
        let (authority, token) = base();
        let bound = attenuate(
            &token,
            &kp(1),
            vec![Caveat::BoundToHolder(node(5))],
            kp(9).public(),
        );
        let eff = verify(&bound, &authority.public()).unwrap();
        assert!(
            authorizes(&eff, "db:write:x", 105, &node(5)),
            "the bound holder may use it"
        );
        assert!(
            !authorizes(&eff, "db:write:x", 105, &node(7)),
            "another holder may not"
        );
    }
}

// -- CAP2: quorum issuance over the release protocol -------------------------

use citadel_mesh::release::ReleaseAuthorization;

/// The release secret-class id for a capability request (CAP-C1): a node requests
/// a capability the same way it requests a sealed secret, so the assigned
/// witnesses vote on its current trust and a quorum authorizes issuance. Stable
/// per (holder, scope).
pub fn capability_secret_id(holder: NodeId, scope: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"citadel-capability\x00");
    h.update(&holder.0);
    h.update(scope.as_bytes());
    *h.finalize().as_bytes()
}

/// Mint a capability **iff the mesh authorized it** (CAP2): the
/// [`ReleaseAuthorization`] must be a satisfied quorum of the capability's
/// eligible witnesses, for this exact (holder, scope). Otherwise refuse — the
/// authority issues no capability without live mesh agreement, exactly like MSS
/// `open` releases no bytes without it. `authority` is the mesh's
/// capability-issuing key (a single key here models the role; distributed via
/// MSS6 threshold signing).
pub fn grant(
    authority: &MeshKeypair,
    capability: Capability,
    quorum: usize,
    auth: &ReleaseAuthorization,
    eligible: &[(NodeId, MeshPublicKey)],
) -> Option<CapabilityToken> {
    if auth.secret_id != capability_secret_id(capability.holder, &capability.scope)
        || auth.requester != capability.holder
        || !auth.satisfies(quorum, eligible)
    {
        return None;
    }
    Some(mint(authority, capability))
}

#[cfg(test)]
mod issuance_tests {
    use super::*;
    use citadel_mesh::crypto::MeshKeypair;
    use citadel_mesh::release::{ReleaseRequest, ReleaseVote};

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }

    #[test]
    fn capability_is_minted_only_with_a_satisfied_quorum() {
        let holder = idk(1);
        let scope = "deploy:prod";
        let secret_id = capability_secret_id(holder.0, scope);
        let quorum = 3;

        // Five assigned witnesses (with keys) and the requester's request.
        let witnesses: Vec<(NodeId, MeshKeypair)> = (10u8..=14).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> = witnesses
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect();
        let req =
            ReleaseRequest::create(&holder.1, holder.0, secret_id, [9u8; 32], quorum, 5, 100, 5);

        let approve = |take: usize| ReleaseAuthorization {
            secret_id,
            requester: holder.0,
            nonce: req.nonce,
            votes: witnesses
                .iter()
                .take(take)
                .map(|(id, kp)| ReleaseVote::sign(kp, &req, *id, true, 6))
                .collect(),
        };

        let authority = MeshKeypair::from_seed([99; 32]);
        let cap = Capability {
            scope: scope.to_string(),
            holder: holder.0,
            beacon_round: 100,
            lease_ticks: 10,
        };

        // A quorum of approvals → granted; the token verifies + authorizes.
        let token =
            grant(&authority, cap.clone(), quorum, &approve(quorum), &eligible).expect("granted");
        let eff = verify(&token, &authority.public()).unwrap();
        assert!(authorizes(&eff, "deploy:prod:svc-a", 105, &holder.0));

        // Below quorum → refused.
        assert!(grant(
            &authority,
            cap.clone(),
            quorum,
            &approve(quorum - 1),
            &eligible
        )
        .is_none());

        // An authorization for a different scope (secret-id mismatch) → refused.
        let other = Capability {
            scope: "deploy:staging".to_string(),
            ..cap
        };
        assert!(grant(&authority, other, quorum, &approve(quorum), &eligible).is_none());
    }
}
