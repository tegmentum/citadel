//! # citadel-federation (FED1) — cross-mesh trust bridging
//!
//! Bridge trust between meshes/sites under explicit, attenuating policy — the
//! SPIFFE-federation analog for the trust fabric. A mesh exports a **signed
//! `TrustBundle`** of its trust facts; another mesh **imports** it under a policy
//! that *translates and limits* the claims.
//!
//! Design calls: a bridge **translates, it doesn't merge** (FED-C1) — the
//! importer maps the remote mesh's claims into its own namespace and **can only
//! downgrade**, never elevate; no mesh dissolves into another. The bundle is
//! signed by the exporting mesh's authority, so an importer trusts a specific
//! issuer, not "anyone." Cross-mesh policy can require the device **tier**
//! (`tpm_spec`, T3) and bound claim **freshness** by beacon round (FED-C3, MB), so
//! a weaker remote mesh is limited in what it can vouch for.
//!
//! FED1 is the pure core (bundle + import policy + translation). FED2 makes the
//! authority to bridge itself a **capability** (`citadel-caps`, FED-C2) and
//! exchanges bundles over a transport; FED3 is multi-mesh deployment.

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};
use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;
use serde::{Deserialize, Serialize};

/// A trust strength rank for federation capping (higher = more trusted). Negative
/// states keep low ranks so a remote negative never imports as positive.
fn rank(t: TrustState) -> u8 {
    match t {
        TrustState::Retired => 0,
        TrustState::Untrusted => 1,
        TrustState::Isolated => 2,
        TrustState::Suspicious => 3,
        TrustState::Unknown => 4,
        TrustState::Degraded => 5,
        TrustState::ProvisionallyAdmitted => 6,
        TrustState::Probationary => 7,
        TrustState::Trusted => 8,
    }
}

/// Limit `remote` to at most `ceiling` — the federation downgrade (FED-C1): the
/// imported trust is whichever is *weaker*.
fn cap(remote: TrustState, ceiling: TrustState) -> TrustState {
    if rank(remote) <= rank(ceiling) {
        remote
    } else {
        ceiling
    }
}

/// One claim in a bundle: the exporting mesh's assessment of one of its nodes,
/// with the device tier and the beacon round it was made at.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustClaim {
    pub subject: NodeId,
    pub trust: TrustState,
    pub tpm_spec: Option<String>,
    pub beacon_round: u64,
}

/// A mesh's exportable, signed trust facts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustBundle {
    pub origin_mesh: String,
    pub issuer: MeshPublicKey,
    pub claims: Vec<TrustClaim>,
    pub signature: Signature,
}

impl TrustBundle {
    fn signing_bytes(origin_mesh: &str, claims: &[TrustClaim]) -> Vec<u8> {
        serde_json::to_vec(&("citadel-trust-bundle", origin_mesh, claims)).expect("serializable")
    }

    /// Export + sign a bundle with the mesh's authority key.
    pub fn sign(issuer: &MeshKeypair, origin_mesh: &str, claims: Vec<TrustClaim>) -> Self {
        let signature = issuer.sign(&Self::signing_bytes(origin_mesh, &claims));
        TrustBundle {
            origin_mesh: origin_mesh.to_string(),
            issuer: issuer.public(),
            claims,
            signature,
        }
    }

    /// Verify the bundle was signed by its claimed issuer.
    pub fn verify(&self) -> bool {
        self.issuer.verify(
            &Self::signing_bytes(&self.origin_mesh, &self.claims),
            &self.signature,
        )
    }
}

/// The importer's policy: which issuer it trusts to bridge, the ceiling trust a
/// remote claim may map to, an optional required device tier, and a freshness
/// bound in beacon rounds.
#[derive(Clone, Debug)]
pub struct ImportPolicy {
    pub trusted_issuer: MeshPublicKey,
    pub max_trust: TrustState,
    pub require_tpm_spec: Option<String>,
    pub max_age_rounds: u64,
}

/// A translated remote claim in the importer's namespace, tagged with its origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedTrust {
    pub subject: NodeId,
    pub origin_mesh: String,
    pub trust: TrustState,
}

/// Why a whole bundle was rejected (per-claim drops aren't errors — they're just
/// excluded from the result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The bundle isn't from the issuer this importer federates with.
    UntrustedIssuer,
    /// The bundle's signature doesn't verify.
    BadSignature,
}

/// Import a bundle under `policy` at `current_round`: verify the issuer + the
/// signature, then translate each claim — dropping stale or wrong-tier ones and
/// **capping** trust to the policy ceiling (downgrade-only, FED-C1).
pub fn import(
    bundle: &TrustBundle,
    policy: &ImportPolicy,
    current_round: u64,
) -> Result<Vec<FederatedTrust>, ImportError> {
    if bundle.issuer != policy.trusted_issuer {
        return Err(ImportError::UntrustedIssuer);
    }
    if !bundle.verify() {
        return Err(ImportError::BadSignature);
    }
    let mut out = Vec::new();
    for claim in &bundle.claims {
        // Freshness bound (FED-C3 / MB).
        if current_round.saturating_sub(claim.beacon_round) > policy.max_age_rounds {
            continue;
        }
        // Device-tier requirement (FED-C3 / T3).
        if let Some(req) = &policy.require_tpm_spec {
            if claim.tpm_spec.as_deref() != Some(req.as_str()) {
                continue;
            }
        }
        out.push(FederatedTrust {
            subject: claim.subject,
            origin_mesh: bundle.origin_mesh.clone(),
            trust: cap(claim.trust, policy.max_trust),
        });
    }
    Ok(out)
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

    fn claim(n: u8, trust: TrustState, spec: Option<&str>, round: u64) -> TrustClaim {
        TrustClaim {
            subject: node(n),
            trust,
            tpm_spec: spec.map(String::from),
            beacon_round: round,
        }
    }

    #[test]
    fn bundle_signs_and_verifies() {
        let issuer = kp(1);
        let b = TrustBundle::sign(
            &issuer,
            "mesh-a",
            vec![claim(7, TrustState::Trusted, Some("2.0"), 100)],
        );
        assert!(b.verify());
        let mut tampered = b.clone();
        tampered.claims[0].trust = TrustState::Untrusted;
        assert!(
            !tampered.verify(),
            "tampering with a claim breaks the bundle signature"
        );
    }

    #[test]
    fn import_translates_and_only_downgrades() {
        let issuer = kp(1);
        let b = TrustBundle::sign(
            &issuer,
            "mesh-a",
            vec![
                claim(7, TrustState::Trusted, Some("2.0"), 100),
                claim(8, TrustState::Suspicious, Some("2.0"), 100),
            ],
        );
        // Remote Trusted is capped to the local ceiling (Probationary); a remote
        // Suspicious stays Suspicious (a negative never imports as positive).
        let policy = ImportPolicy {
            trusted_issuer: issuer.public(),
            max_trust: TrustState::Probationary,
            require_tpm_spec: None,
            max_age_rounds: 50,
        };
        let view = import(&b, &policy, 120).unwrap();
        assert_eq!(
            view[0],
            FederatedTrust {
                subject: node(7),
                origin_mesh: "mesh-a".into(),
                trust: TrustState::Probationary
            }
        );
        assert_eq!(view[1].trust, TrustState::Suspicious);
    }

    #[test]
    fn import_drops_stale_and_wrong_tier_and_untrusted_issuers() {
        let issuer = kp(1);
        let b = TrustBundle::sign(
            &issuer,
            "mesh-a",
            vec![
                claim(1, TrustState::Trusted, Some("2.0"), 100), // fresh, 2.0
                claim(2, TrustState::Trusted, Some("2.0"), 40),  // stale (age 80 > 50)
                claim(3, TrustState::Trusted, Some("1.2"), 100), // wrong tier
            ],
        );
        let policy = ImportPolicy {
            trusted_issuer: issuer.public(),
            max_trust: TrustState::Trusted,
            require_tpm_spec: Some("2.0".into()),
            max_age_rounds: 50,
        };
        let view = import(&b, &policy, 120).unwrap();
        assert_eq!(view.len(), 1, "only the fresh 2.0 claim survives");
        assert_eq!(view[0].subject, node(1));

        // A bundle from an issuer this importer doesn't federate with is rejected.
        let other = ImportPolicy {
            trusted_issuer: kp(99).public(),
            ..policy
        };
        assert_eq!(import(&b, &other, 120), Err(ImportError::UntrustedIssuer));
    }
}

// -- FED2: the bridge is itself a capability + bundle transport --------------

use citadel_caps::{CapabilityToken, Decision, Pep};

impl TrustBundle {
    /// Serialize for exchange over a transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("bundle is serializable")
    }
    /// Deserialize a received bundle.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

/// The capability scope that authorizes bridging a given origin mesh — the
/// authority to federate is a mesh-issued, lease-bound, revocable capability
/// (FED-C2), so a federation link is continuously earned like everything else.
pub fn bridge_scope(origin_mesh: &str) -> String {
    format!("federate:{origin_mesh}")
}

/// Why a gated import was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FedError {
    /// No valid bridge capability authorizes federating this origin.
    Unauthorized,
    /// The bundle itself failed verification.
    Import(ImportError),
}

/// Import a bundle **only** behind a valid bridge capability (FED-C2): the
/// presented `bridge_token` must authorize `federate:<origin>` (verified by the
/// importer's `Pep`), then the bundle is verified + translated as in [`import`].
/// An expired or wrong-origin bridge capability refuses the whole exchange.
pub fn import_gated(
    bundle: &TrustBundle,
    policy: &ImportPolicy,
    current_round: u64,
    pep: &Pep,
    bridge_token: &CapabilityToken,
    holder: &NodeId,
) -> Result<Vec<FederatedTrust>, FedError> {
    let scope = bridge_scope(&bundle.origin_mesh);
    if pep.authorize(bridge_token, &scope, current_round, holder) != Decision::Allow {
        return Err(FedError::Unauthorized);
    }
    import(bundle, policy, current_round).map_err(FedError::Import)
}

#[cfg(test)]
mod fed2_tests {
    use super::*;
    use citadel_caps::{mint, Capability};
    use citadel_mesh::crypto::MeshKeypair;

    fn kp(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([n; 32])
    }
    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn federation_requires_a_valid_bridge_capability() {
        // mesh-a exports a signed bundle.
        let exporter = kp(1);
        let bundle = TrustBundle::sign(
            &exporter,
            "mesh-a",
            vec![TrustClaim {
                subject: node(7),
                trust: TrustState::Trusted,
                tpm_spec: Some("2.0".into()),
                beacon_round: 100,
            }],
        );
        // round-trips over a transport.
        assert!(TrustBundle::from_bytes(&bundle.to_bytes())
            .unwrap()
            .verify());

        let policy = ImportPolicy {
            trusted_issuer: exporter.public(),
            max_trust: TrustState::Trusted,
            require_tpm_spec: None,
            max_age_rounds: 50,
        };

        // The local mesh's capability authority + a bridge operator.
        let cap_authority = kp(2);
        let pep = Pep::new(cap_authority.public());
        let operator = node(5);
        let bridge_cap = |scope: &str, lease: u64| {
            mint(
                &cap_authority,
                Capability {
                    scope: scope.to_string(),
                    holder: operator,
                    beacon_round: 100,
                    lease_ticks: lease,
                },
            )
        };

        // A valid `federate:mesh-a` capability → the bridge imports.
        let ok = bridge_cap("federate:mesh-a", 50);
        let view = import_gated(&bundle, &policy, 120, &pep, &ok, &operator).unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].subject, node(7));

        // A capability for a different origin → unauthorized.
        let wrong_origin = bridge_cap("federate:mesh-z", 50);
        assert_eq!(
            import_gated(&bundle, &policy, 120, &pep, &wrong_origin, &operator),
            Err(FedError::Unauthorized)
        );

        // An expired bridge capability → unauthorized (revocable at renewal).
        let expired = bridge_cap("federate:mesh-a", 5);
        assert_eq!(
            import_gated(&bundle, &policy, 200, &pep, &expired, &operator),
            Err(FedError::Unauthorized)
        );
    }
}
