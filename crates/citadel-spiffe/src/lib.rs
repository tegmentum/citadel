//! # citadel-spiffe — mesh trust gates workload identity (SP1)
//!
//! Citadel does not replace SPIFFE/SPIRE; it becomes the **trust authority** that
//! decides whether SPIRE may issue, renew, or must revoke a workload's SVID. This
//! crate is the pure, testable core of that decision: SPIFFE naming, the
//! categorical-trust → trust-level mapping, the issuance/renewal/revocation
//! decision, and the **derived** `citadel:` selectors. The gRPC SPIRE-plugin
//! shell that exposes this to a live SPIRE server is a separate, deployment-scoped
//! layer (`spiffe-roadmap.md`, SP2).
//!
//! Design calls: continuous identity reuses the MSS lease + deny-at-renewal model
//! (SP2); trust is categorical, never a score (SP3); selectors are computed from
//! verified mesh state, never node-asserted (SP4).

use citadel_mesh::state::TrustState;
use citadel_mesh::NodeId;

/// A SPIFFE trust domain (e.g. `citadel.local`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustDomain(pub String);

impl TrustDomain {
    pub fn new(name: impl Into<String>) -> Self {
        TrustDomain(name.into())
    }
}

impl Default for TrustDomain {
    fn default() -> Self {
        TrustDomain("citadel.local".to_string())
    }
}

/// A SPIFFE ID: `spiffe://<trust-domain><path>` where `path` starts with `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpiffeId {
    pub trust_domain: TrustDomain,
    pub path: String,
}

impl SpiffeId {
    /// A node identity: `spiffe://<td>/node/<mesh-node-id-hex>`.
    pub fn node(td: &TrustDomain, node: &NodeId) -> Self {
        SpiffeId {
            trust_domain: td.clone(),
            path: format!("/node/{}", hex(&node.0)),
        }
    }

    /// A workload identity: `spiffe://<td>/workload/<service>`.
    pub fn workload(td: &TrustDomain, service: &str) -> Self {
        SpiffeId {
            trust_domain: td.clone(),
            path: format!("/workload/{service}"),
        }
    }

    /// A cluster identity: `spiffe://<td>/cluster/<name>`.
    pub fn cluster(td: &TrustDomain, name: &str) -> Self {
        SpiffeId {
            trust_domain: td.clone(),
            path: format!("/cluster/{name}"),
        }
    }

    /// Parse a `spiffe://<td><path>` URI.
    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix("spiffe://")?;
        let slash = rest.find('/')?;
        let (td, path) = rest.split_at(slash);
        if td.is_empty() || path.is_empty() {
            return None;
        }
        Some(SpiffeId {
            trust_domain: TrustDomain(td.to_string()),
            path: path.to_string(),
        })
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spiffe://{}{}", self.trust_domain.0, self.path)
    }
}

/// The four SPIFFE trust levels (SP3) the mesh's categorical [`TrustState`] maps
/// onto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustLevel {
    /// TPM + IMA valid, mesh consensus achieved — full issuance.
    Verified,
    /// Drift or insufficient consensus — existing identities continue, new denied.
    Suspect,
    /// Compromise suspected — no new identities, existing revoked.
    Quarantined,
    /// Compromise confirmed — complete isolation.
    Revoked,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Verified => "verified",
            TrustLevel::Suspect => "suspect",
            TrustLevel::Quarantined => "quarantined",
            TrustLevel::Revoked => "revoked",
        }
    }

    /// Map Citadel's categorical mesh trust onto a SPIFFE trust level (SP3).
    pub fn from_trust_state(t: TrustState) -> Self {
        match t {
            TrustState::Trusted => TrustLevel::Verified,
            TrustState::ProvisionallyAdmitted
            | TrustState::Probationary
            | TrustState::Degraded
            | TrustState::Untrusted
            | TrustState::Unknown => TrustLevel::Suspect,
            TrustState::Suspicious => TrustLevel::Quarantined,
            TrustState::Isolated | TrustState::Retired => TrustLevel::Revoked,
        }
    }
}

/// What SPIRE may do for a node at a given trust level (SP2: continuous identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuanceDecision {
    /// Issue new SVIDs and renew existing ones.
    Issue,
    /// Renew existing SVIDs only; deny new identities.
    RenewOnly,
    /// Actively revoke existing SVIDs and deny new ones (quarantine).
    Revoke,
    /// Complete isolation: deny everything and ensure revoked.
    Deny,
}

impl IssuanceDecision {
    pub fn for_level(level: TrustLevel) -> Self {
        match level {
            TrustLevel::Verified => IssuanceDecision::Issue,
            TrustLevel::Suspect => IssuanceDecision::RenewOnly,
            TrustLevel::Quarantined => IssuanceDecision::Revoke,
            TrustLevel::Revoked => IssuanceDecision::Deny,
        }
    }

    /// May a *new* identity be issued?
    pub fn may_issue_new(&self) -> bool {
        matches!(self, IssuanceDecision::Issue)
    }

    /// May an *existing* SVID be renewed? (The deny-at-renewal gate, SP2.)
    pub fn may_renew(&self) -> bool {
        matches!(self, IssuanceDecision::Issue | IssuanceDecision::RenewOnly)
    }

    /// Must existing SVIDs be actively revoked / kept revoked?
    pub fn must_revoke(&self) -> bool {
        matches!(self, IssuanceDecision::Revoke | IssuanceDecision::Deny)
    }
}

/// The source of mesh trust for identity decisions (SP5) — implemented by the
/// control plane, which derives categorical trust from the verified verdicts.
pub trait TrustProvider {
    /// This node's current categorical trust, if known to the provider.
    fn trust_state(&self, node: &NodeId) -> Option<TrustState>;

    /// The node's SPIFFE trust level (unknown → `Suspect`: deny new, revoke
    /// nothing).
    fn trust_level(&self, node: &NodeId) -> TrustLevel {
        TrustLevel::from_trust_state(self.trust_state(node).unwrap_or(TrustState::Unknown))
    }

    /// What SPIRE may do for this node right now.
    fn decision(&self, node: &NodeId) -> IssuanceDecision {
        IssuanceDecision::for_level(self.trust_level(node))
    }
}

/// A node's verified mesh state, the input to its derived `citadel:` selectors
/// (SP4). Built by the trust source from the agreement + the node's evidence —
/// never asserted by the node itself.
#[derive(Clone, Debug)]
pub struct NodeTrustView {
    pub trust_level: TrustLevel,
    /// Witnesses that agree vs. the total that reported (0/0 = unobserved).
    pub quorum_agree: usize,
    pub quorum_total: usize,
    /// Verified evidence pins, when known.
    pub ima_policy: Option<String>,
    pub tpm_ak: Option<String>,
    pub mma_profile: Option<String>,
}

impl NodeTrustView {
    /// `healthy` (unanimous), `degraded` (split), or `none` (unobserved).
    pub fn quorum_state(&self) -> &'static str {
        if self.quorum_total == 0 {
            "none"
        } else if self.quorum_agree == self.quorum_total {
            "healthy"
        } else {
            "degraded"
        }
    }

    /// The `citadel:` selectors SPIRE matches registration entries against — all
    /// derived from verified state (SP4).
    pub fn selectors(&self) -> Vec<String> {
        let mut s = vec![
            format!("citadel:trust-level={}", self.trust_level.as_str()),
            format!("citadel:quorum-state={}", self.quorum_state()),
        ];
        if let Some(p) = &self.ima_policy {
            s.push(format!("citadel:ima-policy={p}"));
        }
        if let Some(ak) = &self.tpm_ak {
            s.push(format!("citadel:tpm-ak={ak}"));
        }
        if let Some(m) = &self.mma_profile {
            s.push(format!("citadel:mma-profile={m}"));
        }
        s
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId([seed; 32])
    }

    #[test]
    fn spiffe_ids_format_and_round_trip() {
        let td = TrustDomain::default();
        let n = SpiffeId::node(&td, &node(0xAB));
        assert_eq!(
            n.to_string(),
            format!("spiffe://citadel.local/node/{}", "ab".repeat(32))
        );
        assert_eq!(
            SpiffeId::workload(&td, "hexis").to_string(),
            "spiffe://citadel.local/workload/hexis"
        );
        assert_eq!(
            SpiffeId::cluster(&td, "alpha").to_string(),
            "spiffe://citadel.local/cluster/alpha"
        );

        let parsed = SpiffeId::parse("spiffe://citadel.local/workload/ragworks").unwrap();
        assert_eq!(parsed.trust_domain, td);
        assert_eq!(parsed.path, "/workload/ragworks");
        assert!(SpiffeId::parse("https://nope").is_none());
    }

    #[test]
    fn trust_state_maps_to_levels_and_decisions() {
        use TrustState::*;
        let expect = [
            (Trusted, TrustLevel::Verified, IssuanceDecision::Issue),
            (
                Probationary,
                TrustLevel::Suspect,
                IssuanceDecision::RenewOnly,
            ),
            (Degraded, TrustLevel::Suspect, IssuanceDecision::RenewOnly),
            (
                Suspicious,
                TrustLevel::Quarantined,
                IssuanceDecision::Revoke,
            ),
            (Isolated, TrustLevel::Revoked, IssuanceDecision::Deny),
            (Retired, TrustLevel::Revoked, IssuanceDecision::Deny),
        ];
        for (state, level, decision) in expect {
            assert_eq!(TrustLevel::from_trust_state(state), level, "{state:?}");
            assert_eq!(IssuanceDecision::for_level(level), decision, "{state:?}");
        }
    }

    #[test]
    fn issuance_gate_is_the_lease_model() {
        // Verified: new + renew. Suspect: renew only. Quarantined: revoke. Revoked: deny.
        assert!(IssuanceDecision::Issue.may_issue_new() && IssuanceDecision::Issue.may_renew());
        assert!(
            !IssuanceDecision::RenewOnly.may_issue_new() && IssuanceDecision::RenewOnly.may_renew()
        );
        assert!(IssuanceDecision::Revoke.must_revoke() && !IssuanceDecision::Revoke.may_renew());
        assert!(IssuanceDecision::Deny.must_revoke() && !IssuanceDecision::Deny.may_issue_new());
    }

    #[test]
    fn selectors_are_derived_from_verified_state() {
        let view = NodeTrustView {
            trust_level: TrustLevel::Verified,
            quorum_agree: 3,
            quorum_total: 3,
            ima_policy: Some("baseline-v3".to_string()),
            tpm_ak: Some("ak-fpr-abcd".to_string()),
            mma_profile: None,
        };
        let s = view.selectors();
        assert!(s.contains(&"citadel:trust-level=verified".to_string()));
        assert!(s.contains(&"citadel:quorum-state=healthy".to_string()));
        assert!(s.contains(&"citadel:ima-policy=baseline-v3".to_string()));
        assert!(s.contains(&"citadel:tpm-ak=ak-fpr-abcd".to_string()));
        assert!(!s.iter().any(|x| x.starts_with("citadel:mma-profile")));

        let split = NodeTrustView {
            quorum_agree: 2,
            quorum_total: 3,
            ..view.clone()
        };
        assert_eq!(split.quorum_state(), "degraded");
        let unobserved = NodeTrustView {
            quorum_agree: 0,
            quorum_total: 0,
            ..view
        };
        assert_eq!(unobserved.quorum_state(), "none");
    }

    // A minimal in-memory TrustProvider exercises the trait defaults.
    struct MockProvider(std::collections::HashMap<[u8; 32], TrustState>);
    impl TrustProvider for MockProvider {
        fn trust_state(&self, node: &NodeId) -> Option<TrustState> {
            self.0.get(&node.0).copied()
        }
    }

    #[test]
    fn trust_provider_drives_the_decision() {
        let mut m = std::collections::HashMap::new();
        m.insert([1u8; 32], TrustState::Trusted);
        m.insert([2u8; 32], TrustState::Suspicious);
        let p = MockProvider(m);
        assert_eq!(p.decision(&node(1)), IssuanceDecision::Issue);
        assert_eq!(p.decision(&node(2)), IssuanceDecision::Revoke);
        // Unknown node → Suspect → deny new, revoke nothing.
        assert_eq!(p.decision(&node(9)), IssuanceDecision::RenewOnly);
    }
}
