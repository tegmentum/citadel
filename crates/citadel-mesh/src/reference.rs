//! Authorized measured-state transitions — the multi-value appraisal engine
//! (design `measured-state-transitions.md`, Phase 1).
//!
//! A verifier no longer holds a single golden it exact-matches; it holds a set
//! of **accepted reference sources** and asks whether a quote's PCRs are
//! *explained* by an active source. Two source shapes coexist:
//!
//! * **standalone per-index entries** ([`ReferenceEntry`]) — independent
//!   components (firmware, Secure Boot, kernel) each keep their own accepted
//!   digests and upgrade independently, with no combinatorial blow-up;
//! * **coupled profiles** ([`ReferenceProfile`]) — a set of `(index, digest)`
//!   pairs accepted only *together* (e.g. kernel + cmdline + initrd, or a
//!   high-assurance whole-image match).
//!
//! Each source carries a [`Validity`] window bounded by either or both of the
//! mesh's clocks (policy-revision generation and logical/wall tick), so a
//! transition can be staged ahead of a rollout and retired after it. Matching
//! only a *retired* source (unpatched, not tampered) is graded by
//! [`RetiredAction`]; matching *nothing known* is always a hard failure.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tpm_core::backend::PcrValue;

use crate::attest::ReferenceMeasurements;

/// Validity window for a reference source, bounded by either or both clocks.
/// An unset bound is unbounded on that side; both set ⇒ both must hold.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    pub from_revision: Option<u64>,
    pub until_revision: Option<u64>,
    pub from_tick: Option<u64>,
    pub until_tick: Option<u64>,
}

/// Where a source sits relative to "now" on the configured clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveState {
    /// Before a `from_*` bound — staged but not yet in effect.
    Pending,
    /// Within bounds — counts toward acceptance.
    Active,
    /// Past an `until_*` bound — withdrawn.
    Retired,
}

impl Validity {
    /// An always-active window (no bounds) — the bootstrap golden.
    pub fn always() -> Self {
        Validity::default()
    }

    /// Effective from a policy-revision generation onward.
    pub fn from_revision(rev: u64) -> Self {
        Validity { from_revision: Some(rev), ..Validity::default() }
    }

    /// Resolve this window against the current `(tick, revision)`.
    pub fn state(&self, now_tick: u64, now_revision: u64) -> ActiveState {
        if self.until_revision.is_some_and(|r| now_revision >= r)
            || self.until_tick.is_some_and(|t| now_tick >= t)
        {
            return ActiveState::Retired;
        }
        if self.from_revision.is_some_and(|r| now_revision < r)
            || self.from_tick.is_some_and(|t| now_tick < t)
        {
            return ActiveState::Pending;
        }
        ActiveState::Active
    }
}

/// How a verifier treats a quote that matches only a **retired** source — i.e.
/// a node on a previously-good but now-withdrawn state (unpatched).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetiredAction {
    /// Retired == untrusted (forces patching hard). The safe default.
    Fail,
    /// Degraded but tolerated.
    Warn,
    /// `Warn` until `grace` past the retirement bound, then `Fail` — a patch
    /// deadline. Grace is measured per clock; a clock that retired the source
    /// with no grace configured fails immediately on that clock.
    GraceThenFail {
        grace_revisions: Option<u64>,
        grace_ticks: Option<u64>,
    },
}

impl Default for RetiredAction {
    fn default() -> Self {
        RetiredAction::Fail
    }
}

impl RetiredAction {
    /// `true` if a source retired with `validity` should still be tolerated
    /// (Warn) rather than failed, at the current `(tick, revision)`.
    fn within_grace(&self, validity: &Validity, now_tick: u64, now_revision: u64) -> bool {
        match self {
            RetiredAction::Fail => false,
            RetiredAction::Warn => true,
            RetiredAction::GraceThenFail { grace_revisions, grace_ticks } => {
                let rev_ok = match (validity.until_revision, grace_revisions) {
                    (Some(until), Some(grace)) => now_revision < until.saturating_add(*grace),
                    (Some(_), None) => false, // retired by revision, no grace
                    (None, _) => true,        // not retired by revision
                };
                let tick_ok = match (validity.until_tick, grace_ticks) {
                    (Some(until), Some(grace)) => now_tick < until.saturating_add(*grace),
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                rev_ok && tick_ok
            }
        }
    }
}

/// Whether standalone entries count, or only fully-satisfied coupled profiles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReferenceMatchPolicy {
    /// Standalone entries and coupled profiles both count (mix freely).
    #[default]
    Flexible,
    /// Ignore standalone entries: every index must be explained by a
    /// fully-satisfied profile (no mix-and-match).
    CoupledOnly,
}

/// A standalone accepted digest for one PCR index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceEntry {
    pub index: u32,
    pub digest: Vec<u8>,
    pub validity: Validity,
}

/// A set of `(index, digest)` pairs accepted only together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProfile {
    pub id: [u8; 32],
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub validity: Validity,
}

impl ReferenceProfile {
    /// Content id of a profile: `BLAKE3` over its sorted `(index, digest)` set.
    pub fn compute_id(pcrs: &BTreeMap<u32, Vec<u8>>) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"citadel-reference-profile\x00");
        for (index, digest) in pcrs {
            h.update(&index.to_be_bytes());
            h.update(digest);
        }
        *h.finalize().as_bytes()
    }

    pub fn new(pcrs: BTreeMap<u32, Vec<u8>>, validity: Validity) -> Self {
        let id = Self::compute_id(&pcrs);
        ReferenceProfile { id, pcrs, validity }
    }

    /// Is this profile satisfied by the quote? Every profile index that the
    /// quote actually provides must match; indices the quote omits can't be
    /// checked and are ignored.
    fn satisfied_by(&self, quoted: &BTreeMap<u32, &[u8]>) -> bool {
        self.pcrs.iter().all(|(index, digest)| match quoted.get(index) {
            Some(q) => *q == digest.as_slice(),
            None => true,
        })
    }
}

/// The result of appraising a quote against the accepted set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceOutcome {
    /// Every quoted index matched an *active* source.
    Accepted,
    /// At least one index matched only a *retired* source; `fail` per the
    /// configured [`RetiredAction`].
    Retired { fail: bool },
    /// An index is covered by a known source but matches none → likely tamper.
    Unknown,
    /// An index has no (active/retired) source at all → can't assert good.
    Incomplete,
}

/// How one quoted PCR relates to the accepted set.
enum IndexClass {
    /// No active/retired source covers this index.
    Uncovered,
    /// An active source matches the quoted digest.
    Active,
    /// Only a retired source matches; carries that source's window for grading.
    Retired(Validity),
    /// Covered by a source, but the quoted digest matches none.
    Mismatch,
}

/// The accepted reference sources a verifier appraises quotes against.
#[derive(Clone, Debug, Default)]
pub struct AcceptedReferences {
    pub bank: String,
    entries: Vec<ReferenceEntry>,
    profiles: Vec<ReferenceProfile>,
}

impl AcceptedReferences {
    pub fn new(bank: impl Into<String>) -> Self {
        AcceptedReferences { bank: bank.into(), entries: Vec::new(), profiles: Vec::new() }
    }

    /// Seed from a single golden [`ReferenceMeasurements`] — one always-active
    /// standalone entry per index (the bootstrap / pre-transition path).
    pub fn from_reference(reference: ReferenceMeasurements) -> Self {
        let entries = reference
            .pcrs
            .iter()
            .map(|(index, digest)| ReferenceEntry {
                index: *index,
                digest: digest.clone(),
                validity: Validity::always(),
            })
            .collect();
        AcceptedReferences { bank: reference.bank, entries, profiles: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.profiles.is_empty()
    }

    /// Add a standalone accepted digest for an index.
    pub fn accept_entry(&mut self, index: u32, digest: Vec<u8>, validity: Validity) {
        self.entries.push(ReferenceEntry { index, digest, validity });
    }

    /// Add a coupled profile (accepted only when fully satisfied).
    pub fn accept_profile(&mut self, pcrs: BTreeMap<u32, Vec<u8>>, validity: Validity) {
        self.profiles.push(ReferenceProfile::new(pcrs, validity));
    }

    /// Classify one quoted `(index, digest)` against the accepted sources.
    fn classify(
        &self,
        index: u32,
        digest: &[u8],
        quoted: &BTreeMap<u32, &[u8]>,
        now_tick: u64,
        now_revision: u64,
        policy: ReferenceMatchPolicy,
    ) -> IndexClass {
        let mut covered = false;
        let mut retired: Option<Validity> = None;

        if policy == ReferenceMatchPolicy::Flexible {
            for e in self.entries.iter().filter(|e| e.index == index) {
                match e.validity.state(now_tick, now_revision) {
                    ActiveState::Active => {
                        covered = true;
                        if e.digest == digest {
                            return IndexClass::Active;
                        }
                    }
                    ActiveState::Retired => {
                        covered = true;
                        if e.digest == digest {
                            retired = Some(e.validity.clone());
                        }
                    }
                    ActiveState::Pending => {}
                }
            }
        }

        for p in self.profiles.iter().filter(|p| p.pcrs.contains_key(&index)) {
            match p.validity.state(now_tick, now_revision) {
                ActiveState::Pending => continue,
                state => {
                    covered = true;
                    if p.satisfied_by(quoted) {
                        match state {
                            ActiveState::Active => return IndexClass::Active,
                            ActiveState::Retired => retired = Some(p.validity.clone()),
                            ActiveState::Pending => {}
                        }
                    }
                }
            }
        }

        match retired {
            Some(v) => IndexClass::Retired(v),
            None if covered => IndexClass::Mismatch,
            None => IndexClass::Uncovered,
        }
    }

    /// Appraise a quote's PCR values against the accepted set. Precedence over
    /// the quoted indices: any `Mismatch` ⇒ `Unknown`; else any `Uncovered` ⇒
    /// `Incomplete`; else any `Retired` ⇒ `Retired`; else `Accepted`.
    pub fn appraise(
        &self,
        quoted: &[PcrValue],
        now_tick: u64,
        now_revision: u64,
        policy: ReferenceMatchPolicy,
        retired_action: RetiredAction,
    ) -> ReferenceOutcome {
        let q: BTreeMap<u32, &[u8]> = quoted.iter().map(|p| (p.index, p.digest.as_slice())).collect();

        let mut any_uncovered = false;
        let mut retired_windows: Vec<Validity> = Vec::new();
        for pv in quoted {
            match self.classify(pv.index, &pv.digest, &q, now_tick, now_revision, policy) {
                IndexClass::Mismatch => return ReferenceOutcome::Unknown,
                IndexClass::Uncovered => any_uncovered = true,
                IndexClass::Retired(v) => retired_windows.push(v),
                IndexClass::Active => {}
            }
        }

        if any_uncovered {
            ReferenceOutcome::Incomplete
        } else if !retired_windows.is_empty() {
            // The harshest retired component decides: fail if any is past grace.
            let fail = retired_windows
                .iter()
                .any(|v| !retired_action.within_grace(v, now_tick, now_revision));
            ReferenceOutcome::Retired { fail }
        } else {
            ReferenceOutcome::Accepted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcr(index: u32, digest: &[u8]) -> PcrValue {
        PcrValue { bank: "sha256".into(), index, digest: digest.to_vec() }
    }

    fn refs() -> AcceptedReferences {
        AcceptedReferences::new("sha256")
    }

    #[test]
    fn active_match_is_accepted() {
        let mut r = refs();
        r.accept_entry(0, b"fw1".to_vec(), Validity::always());
        r.accept_entry(7, b"sb1".to_vec(), Validity::always());
        let q = [pcr(0, b"fw1"), pcr(7, b"sb1")];
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Accepted
        );
    }

    #[test]
    fn covered_but_wrong_is_unknown() {
        let mut r = refs();
        r.accept_entry(0, b"fw1".to_vec(), Validity::always());
        let q = [pcr(0, b"tampered")];
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Unknown
        );
    }

    #[test]
    fn uncovered_index_is_incomplete() {
        let r = refs(); // no sources at all
        let q = [pcr(0, b"fw1")];
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Incomplete
        );
    }

    #[test]
    fn overlap_window_accepts_old_and_new() {
        // Kernel transition: both v1 and v2 active at once.
        let mut r = refs();
        r.accept_entry(4, b"k1".to_vec(), Validity::always());
        r.accept_entry(4, b"k2".to_vec(), Validity::always());
        for d in [b"k1".as_slice(), b"k2".as_slice()] {
            assert_eq!(
                r.appraise(&[pcr(4, d)], 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
                ReferenceOutcome::Accepted
            );
        }
    }

    #[test]
    fn retired_match_obeys_the_action() {
        let mut r = refs();
        // k1 retired at revision 5; k2 always active.
        r.accept_entry(4, b"k1".to_vec(), Validity { until_revision: Some(5), ..Validity::default() });
        let q = [pcr(4, b"k1")];

        // now at revision 10 → k1 is retired.
        assert_eq!(
            r.appraise(&q, 0, 10, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Retired { fail: true }
        );
        assert_eq!(
            r.appraise(&q, 0, 10, ReferenceMatchPolicy::Flexible, RetiredAction::Warn),
            ReferenceOutcome::Retired { fail: false }
        );
        // grace of 10 revisions past until(5) → still within at rev 10.
        let grace = RetiredAction::GraceThenFail { grace_revisions: Some(10), grace_ticks: None };
        assert_eq!(
            r.appraise(&q, 0, 10, ReferenceMatchPolicy::Flexible, grace),
            ReferenceOutcome::Retired { fail: false }
        );
        // past the grace (rev 20 > 5+10) → fail.
        assert_eq!(
            r.appraise(&q, 0, 20, ReferenceMatchPolicy::Flexible, grace),
            ReferenceOutcome::Retired { fail: true }
        );
        // before retirement (rev 3) → still active.
        assert_eq!(
            r.appraise(&q, 0, 3, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Accepted
        );
    }

    #[test]
    fn pending_source_is_not_yet_acceptable() {
        let mut r = refs();
        // k2 only effective from revision 5; nothing else covers PCR 4.
        r.accept_entry(4, b"k2".to_vec(), Validity::from_revision(5));
        let q = [pcr(4, b"k2")];
        // before it's effective → uncovered → Incomplete (no active opinion).
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Incomplete
        );
        // once effective → accepted.
        assert_eq!(
            r.appraise(&q, 0, 5, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Accepted
        );
    }

    #[test]
    fn independent_components_upgrade_separately() {
        // Firmware and kernel each have two accepted values; any mix passes
        // under per-index (Flexible) matching.
        let mut r = refs();
        r.accept_entry(0, b"fw1".to_vec(), Validity::always());
        r.accept_entry(0, b"fw2".to_vec(), Validity::always());
        r.accept_entry(4, b"k1".to_vec(), Validity::always());
        r.accept_entry(4, b"k2".to_vec(), Validity::always());
        let q = [pcr(0, b"fw2"), pcr(4, b"k1")]; // new firmware, old kernel
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Accepted
        );
    }

    #[test]
    fn coupled_profile_rejects_mix_and_match() {
        // Only the pairs (k1,i1) and (k2,i2) ever shipped together.
        let mut r = refs();
        r.accept_profile(
            BTreeMap::from([(4, b"k1".to_vec()), (8, b"i1".to_vec())]),
            Validity::always(),
        );
        r.accept_profile(
            BTreeMap::from([(4, b"k2".to_vec()), (8, b"i2".to_vec())]),
            Validity::always(),
        );

        // A matched pair is accepted.
        let good = [pcr(4, b"k2"), pcr(8, b"i2")];
        assert_eq!(
            r.appraise(&good, 0, 0, ReferenceMatchPolicy::CoupledOnly, RetiredAction::Fail),
            ReferenceOutcome::Accepted
        );
        // A mix-and-match (k2 + i1) satisfies no profile → covered but wrong.
        let mixed = [pcr(4, b"k2"), pcr(8, b"i1")];
        assert_eq!(
            r.appraise(&mixed, 0, 0, ReferenceMatchPolicy::CoupledOnly, RetiredAction::Fail),
            ReferenceOutcome::Unknown
        );
    }

    #[test]
    fn coupled_only_ignores_standalone_entries() {
        let mut r = refs();
        r.accept_entry(4, b"k1".to_vec(), Validity::always());
        let q = [pcr(4, b"k1")];
        // Flexible: standalone counts → accepted.
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Fail),
            ReferenceOutcome::Accepted
        );
        // CoupledOnly: no profile covers PCR 4 → uncovered → Incomplete.
        assert_eq!(
            r.appraise(&q, 0, 0, ReferenceMatchPolicy::CoupledOnly, RetiredAction::Fail),
            ReferenceOutcome::Incomplete
        );
    }

    #[test]
    fn validity_by_tick_clock() {
        let mut r = refs();
        r.accept_entry(0, b"fw1".to_vec(), Validity { until_tick: Some(100), ..Validity::default() });
        let q = [pcr(0, b"fw1")];
        assert_eq!(
            r.appraise(&q, 50, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Warn),
            ReferenceOutcome::Accepted
        );
        assert_eq!(
            r.appraise(&q, 150, 0, ReferenceMatchPolicy::Flexible, RetiredAction::Warn),
            ReferenceOutcome::Retired { fail: false }
        );
    }
}
