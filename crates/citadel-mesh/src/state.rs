//! Liveness and trust state — kept deliberately separate.
//!
//! Citadel must not conflate "down" with "compromised" (design §9.6). A
//! node carries **two** orthogonal states:
//!
//! * [`LivenessState`] — is it responding? (the SWIM failure detector)
//! * [`TrustState`] — is its *evidence* good? (attestation + witnesses)
//!
//! So `Alive + Suspicious` and `Faulty + PreviouslyTrusted` are both
//! valid combinations.

use serde::{Deserialize, Serialize};

/// SWIM liveness state of a member (design §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LivenessState {
    Alive,
    Suspect,
    Faulty,
    Left,
    Retired,
}

impl LivenessState {
    pub fn as_str(&self) -> &'static str {
        match self {
            LivenessState::Alive => "alive",
            LivenessState::Suspect => "suspect",
            LivenessState::Faulty => "faulty",
            LivenessState::Left => "left",
            LivenessState::Retired => "retired",
        }
    }
}

/// Trust state from attestation + witness quorum (design §7.1, §11.1).
///
/// Ordering note: this is a lifecycle, not a total order. Promotion runs
/// `ProvisionallyAdmitted → Probationary → Trusted`; degradation runs
/// `Trusted → Degraded → Suspicious → Isolated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    /// Not yet admitted to the mesh.
    Untrusted,
    /// Passed enrollment quorum; not yet observed over time.
    ProvisionallyAdmitted,
    /// Observed, but may not yet influence trust decisions.
    Probationary,
    /// Evidence matches policy and quorum agrees.
    Trusted,
    /// Minor/recoverable issue (stale policy, missing optional evidence).
    Degraded,
    /// Material inconsistency (failed quote, contradictory observations).
    Suspicious,
    /// Removed from normal participation by quorum/operator.
    Isolated,
    /// Deliberately and permanently removed.
    Retired,
    /// Insufficient evidence to classify.
    Unknown,
}

impl TrustState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustState::Untrusted => "untrusted",
            TrustState::ProvisionallyAdmitted => "provisionally-admitted",
            TrustState::Probationary => "probationary",
            TrustState::Trusted => "trusted",
            TrustState::Degraded => "degraded",
            TrustState::Suspicious => "suspicious",
            TrustState::Isolated => "isolated",
            TrustState::Retired => "retired",
            TrustState::Unknown => "unknown",
        }
    }

    /// Whether a node in this state may influence quorum decisions about
    /// *other* nodes (design §7.5: probation/untrusted nodes may not vote).
    pub fn may_vote(&self) -> bool {
        matches!(self, TrustState::Trusted | TrustState::Degraded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_settled_trust_states_may_vote() {
        assert!(TrustState::Trusted.may_vote());
        assert!(TrustState::Degraded.may_vote());
        assert!(!TrustState::Probationary.may_vote());
        assert!(!TrustState::ProvisionallyAdmitted.may_vote());
        assert!(!TrustState::Suspicious.may_vote());
        assert!(!TrustState::Isolated.may_vote());
    }
}
