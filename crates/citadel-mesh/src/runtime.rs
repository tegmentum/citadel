//! Runtime (IMA) appraisal — extend appraisal from boot into runtime
//! (roadmap C1 / event-log Phase D). Boot appraisal proves *what booted*;
//! this judges *what ran afterward* from the Linux IMA measurement list
//! (PCR 10), so a node that executed a known-bad or unapproved file is caught
//! on its next attestation.
//!
//! Policy is content-hash based, mirroring [`crate::reference::FleetArtifactPolicy`]
//! for boot artifacts:
//! * a **denylist** of known-bad file hashes always fails (the `dbx` analogue);
//! * an optional **allowlist** — when set, only listed file hashes may run
//!   (lockdown / appraise-enforce); empty = report-only (anything runs, but the
//!   log is still preserved and the deny list still applies).

use tpm_core::ima::{ImaEntry, ImaLog};

/// A measured file that violated runtime policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeViolation {
    pub path: String,
    pub algo: String,
    pub hash: Vec<u8>,
    pub reason: RuntimeReason,
}

/// Why a measured file failed runtime policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeReason {
    /// The file's content hash is on the denylist (known-bad).
    Denied,
    /// An allowlist is in force and this file's hash is not on it.
    NotAllowed,
}

/// Fleet runtime-integrity policy over IMA file measurements.
#[derive(Clone, Debug, Default)]
pub struct RuntimePolicy {
    /// Known-bad file hashes `(algo, hash)` — always fail.
    denied: std::collections::BTreeSet<(String, Vec<u8>)>,
    /// Approved file hashes. When non-empty, **only** these may run.
    allowed: std::collections::BTreeSet<(String, Vec<u8>)>,
}

impl RuntimePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a known-bad file hash (denylist; the `dbx` analogue).
    pub fn deny(mut self, algo: impl Into<String>, hash: Vec<u8>) -> Self {
        self.denied.insert((algo.into(), hash));
        self
    }

    /// Add an approved file hash. Once any file is allowed the policy becomes an
    /// allowlist: unlisted files are [`RuntimeReason::NotAllowed`].
    pub fn allow(mut self, algo: impl Into<String>, hash: Vec<u8>) -> Self {
        self.allowed.insert((algo.into(), hash));
        self
    }

    /// Whether an allowlist is in force (any file has been explicitly allowed).
    pub fn is_allowlist(&self) -> bool {
        !self.allowed.is_empty()
    }

    /// Judge one IMA entry against the policy.
    fn judge(&self, e: &ImaEntry) -> Option<RuntimeReason> {
        let key = (e.file_algo.clone(), e.file_hash.clone());
        if self.denied.contains(&key) {
            return Some(RuntimeReason::Denied);
        }
        if self.is_allowlist() && !self.allowed.contains(&key) {
            return Some(RuntimeReason::NotAllowed);
        }
        None
    }

    /// Appraise a parsed IMA log: return every measured file that violates the
    /// policy, in log order. Empty result = clean. (Report-always: a violation
    /// is *returned*, not silently dropped — the caller decides whether to
    /// quarantine, escalate node trust, or just report, mirroring the
    /// application-appraisal graded response.)
    pub fn appraise(&self, log: &ImaLog) -> Vec<RuntimeViolation> {
        log.entries
            .iter()
            .filter_map(|e| {
                self.judge(e).map(|reason| RuntimeViolation {
                    path: e.path.clone(),
                    algo: e.file_algo.clone(),
                    hash: e.file_hash.clone(),
                    reason,
                })
            })
            .collect()
    }

    /// Convenience: parse the ASCII IMA list and appraise it. Returns the
    /// violations and the number of unparseable lines skipped.
    pub fn appraise_ascii(&self, ascii: &str) -> (Vec<RuntimeViolation>, usize) {
        let (log, skipped) = ImaLog::parse_ascii(ascii);
        (self.appraise(&log), skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NG1: &str =
        "10 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ima-ng sha256:1111111111111111111111111111111111111111111111111111111111111111 /usr/bin/bash";
    const NG2: &str =
        "10 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ima-ng sha256:2222222222222222222222222222222222222222222222222222222222222222 /tmp/evil";

    #[test]
    fn denylist_flags_a_known_bad_file() {
        let log = format!("{NG1}\n{NG2}\n");
        let policy = RuntimePolicy::new().deny("sha256", vec![0x22; 32]);
        let (v, skipped) = policy.appraise_ascii(&log);
        assert_eq!(skipped, 0);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].path, "/tmp/evil");
        assert_eq!(v[0].reason, RuntimeReason::Denied);
    }

    #[test]
    fn allowlist_flags_everything_not_listed() {
        let log = format!("{NG1}\n{NG2}\n");
        // Allow only bash → /tmp/evil is NotAllowed.
        let policy = RuntimePolicy::new().allow("sha256", vec![0x11; 32]);
        assert!(policy.is_allowlist());
        let (v, _) = policy.appraise_ascii(&log);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].path, "/tmp/evil");
        assert_eq!(v[0].reason, RuntimeReason::NotAllowed);
    }

    #[test]
    fn empty_policy_is_report_only_clean() {
        let log = format!("{NG1}\n{NG2}\n");
        let (v, _) = RuntimePolicy::new().appraise_ascii(&log);
        assert!(v.is_empty(), "no policy → nothing flagged");
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let log = format!("{NG1}\n");
        // bash is both allowed and (later) denied → denied wins.
        let policy = RuntimePolicy::new()
            .allow("sha256", vec![0x11; 32])
            .deny("sha256", vec![0x11; 32]);
        let (v, _) = policy.appraise_ascii(&log);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].reason, RuntimeReason::Denied);
    }
}
