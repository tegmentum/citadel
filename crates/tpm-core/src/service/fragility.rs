//! Policy fragility analysis.
//!
//! Rates PCR-based policies by how likely they are to break under
//! expected platform events like firmware updates, kernel upgrades,
//! or secure boot configuration changes.

use serde::{Deserialize, Serialize};

use crate::model::{Policy, PolicyRule};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FragilityRating {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for FragilityRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrFragility {
    pub bank: String,
    pub index: u32,
    pub rating: FragilityRating,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragilityReport {
    pub overall: FragilityRating,
    pub per_pcr: Vec<PcrFragility>,
    pub notes: Vec<String>,
}

/// Classify a PCR by its typical volatility across boot events.
fn classify_pcr(index: u32) -> (FragilityRating, &'static str) {
    match index {
        0 => (
            FragilityRating::High,
            "firmware code (changes on BIOS/UEFI updates)",
        ),
        1 => (
            FragilityRating::High,
            "firmware configuration (changes on BIOS setting changes)",
        ),
        2 => (
            FragilityRating::Medium,
            "option ROMs (changes if add-in cards change)",
        ),
        3 => (FragilityRating::Medium, "option ROM configuration"),
        4 => (
            FragilityRating::High,
            "MBR / boot manager code (changes on bootloader updates)",
        ),
        5 => (
            FragilityRating::High,
            "MBR / partition table (changes on disk layout changes)",
        ),
        6 => (
            FragilityRating::Medium,
            "state transitions and resume events",
        ),
        7 => (
            FragilityRating::Medium,
            "Secure Boot state (stable unless SB keys change)",
        ),
        8 => (
            FragilityRating::High,
            "GRUB / bootloader config (changes on kernel upgrades)",
        ),
        9 => (FragilityRating::High, "GRUB modules / kernel command line"),
        10 => (
            FragilityRating::High,
            "IMA measurements (high churn under normal use)",
        ),
        11 => (
            FragilityRating::High,
            "OS kernel / systemd (changes on kernel updates)",
        ),
        12 => (FragilityRating::Medium, "boot authorities"),
        13 => (FragilityRating::Medium, "platform boot data"),
        14 => (
            FragilityRating::Medium,
            "MOK / shim (changes if MOK list updates)",
        ),
        15 => (FragilityRating::Medium, "platform measurement authority"),
        16 => (
            FragilityRating::Low,
            "debug PCR (application-controlled, low volatility)",
        ),
        17..=22 => (
            FragilityRating::Low,
            "reserved / DRTM PCR (rarely used in policy)",
        ),
        23 => (
            FragilityRating::Low,
            "application PCR (explicitly controlled by operator)",
        ),
        _ => (FragilityRating::Medium, "unknown PCR index"),
    }
}

/// Rate a compiled policy by boot-sensitivity.
pub fn rate_policy(policy: &Policy) -> FragilityReport {
    let mut per_pcr = Vec::new();
    let mut has_auth_value = false;

    for rule in &policy.rules {
        match rule {
            PolicyRule::PcrMatch { bank, indices } => {
                for &index in indices {
                    let (rating, reason) = classify_pcr(index);
                    per_pcr.push(PcrFragility {
                        bank: bank.clone(),
                        index,
                        rating,
                        reason: reason.to_string(),
                    });
                }
            }
            PolicyRule::Password => {
                has_auth_value = true;
            }
        }
    }

    // Overall = max rating across PCRs
    let overall = per_pcr
        .iter()
        .map(|p| p.rating)
        .max_by_key(|r| match r {
            FragilityRating::Low => 0,
            FragilityRating::Medium => 1,
            FragilityRating::High => 2,
        })
        .unwrap_or(FragilityRating::Low);

    let mut notes = Vec::new();
    if policy.rules.is_empty() {
        notes.push("policy has no requirements — satisfied unconditionally".to_string());
    }
    if has_auth_value {
        notes.push("policy also requires an auth value (password)".to_string());
    }
    if per_pcr.iter().any(|p| p.rating == FragilityRating::High) {
        notes.push(
            "at least one PCR is high-churn: expect breakage under firmware/kernel/bootloader updates"
                .to_string(),
        );
    }
    if per_pcr.iter().all(|p| p.index == 7) && !per_pcr.is_empty() {
        notes.push(
            "policy is bound only to Secure Boot state (PCR 7); stable unless SB keys change"
                .to_string(),
        );
    }

    FragilityReport {
        overall,
        per_pcr,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Policy, PolicyRule};
    use uuid::Uuid;

    fn mk_policy(rules: Vec<PolicyRule>) -> Policy {
        Policy {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            rules,
        }
    }

    #[test]
    fn empty_policy_is_low() {
        let p = mk_policy(vec![]);
        let r = rate_policy(&p);
        assert_eq!(r.overall, FragilityRating::Low);
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn pcr_0_is_high() {
        let p = mk_policy(vec![PolicyRule::PcrMatch {
            bank: "sha256".to_string(),
            indices: vec![0],
        }]);
        let r = rate_policy(&p);
        assert_eq!(r.overall, FragilityRating::High);
    }

    #[test]
    fn pcr_16_is_low() {
        let p = mk_policy(vec![PolicyRule::PcrMatch {
            bank: "sha256".to_string(),
            indices: vec![16],
        }]);
        let r = rate_policy(&p);
        assert_eq!(r.overall, FragilityRating::Low);
    }

    #[test]
    fn mixed_pcrs_take_max() {
        let p = mk_policy(vec![PolicyRule::PcrMatch {
            bank: "sha256".to_string(),
            indices: vec![7, 11, 16],
        }]);
        let r = rate_policy(&p);
        // PCR 11 is high -> overall high
        assert_eq!(r.overall, FragilityRating::High);
        assert_eq!(r.per_pcr.len(), 3);
    }

    #[test]
    fn pcr_7_only_is_medium() {
        let p = mk_policy(vec![PolicyRule::PcrMatch {
            bank: "sha256".to_string(),
            indices: vec![7],
        }]);
        let r = rate_policy(&p);
        assert_eq!(r.overall, FragilityRating::Medium);
        assert!(r.notes.iter().any(|n| n.contains("Secure Boot")));
    }

    #[test]
    fn password_adds_note() {
        let p = mk_policy(vec![
            PolicyRule::PcrMatch {
                bank: "sha256".to_string(),
                indices: vec![16],
            },
            PolicyRule::Password,
        ]);
        let r = rate_policy(&p);
        assert!(r.notes.iter().any(|n| n.contains("auth value")));
    }
}
