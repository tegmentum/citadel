//! Measured-boot event log: ingestion, replay, and the `replay == quote`
//! integrity check (design `event-log-attestation.md`, Phase A).
//!
//! PCRs are lossy: they prove *that* a sequence of measurements happened, not
//! *what* each was. The event log is that sequence. Replaying it — folding each
//! event's digest into its PCR in order — must reproduce the TPM-signed quoted
//! PCR values; because PCR extension is a preimage-resistant hash-chain, a log
//! that replays to a genuine quote is the authentic, complete explanation of it
//! (a forged/omitted/reordered log cannot).
//!
//! Phase A delivers the replay engine and a Citadel-internal serialization
//! (`to_bytes`/`from_bytes`). Parsing the real TCG binary formats
//! (`TCG_PCR_EVENT2`) is Phase B.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::backend::{bank_digest_size, pcr_fold, PcrValue};

/// The kind of a measured-boot event (minimal for Phase A; real `EV_*` types
/// arrive with TCG binary parsing in Phase B).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Does not extend the PCR; a leading `NoAction` *sets* the PCR's base
    /// value (the TCG `StartupLocality` pattern), so a verifier can replay a
    /// PCR whose firmware base is not zero.
    NoAction,
    /// A normal measurement that extends its PCR.
    Extend,
    /// An unrecognised TCG event type, carried opaquely (treated as `Extend`).
    Unknown(u32),
}

/// One parsed measured-boot event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementEvent {
    pub pcr: u32,
    pub event_type: EventType,
    /// One digest per hash bank, keyed by bank name (e.g. `"sha256"`).
    pub digests: Vec<(String, Vec<u8>)>,
    /// Opaque event data. NOT PCR-bound (only the digest is) — trust it only
    /// to the extent it is reflected in the digest (design §3).
    pub data: Vec<u8>,
}

impl MeasurementEvent {
    fn digest_for(&self, bank: &str) -> Option<&[u8]> {
        self.digests.iter().find(|(b, _)| b == bank).map(|(_, d)| d.as_slice())
    }
}

/// A parsed measured-boot log. (Named to avoid clashing with the LtHash
/// `logship::EventLog`.)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEventLog {
    pub events: Vec<MeasurementEvent>,
}

impl BootEventLog {
    pub fn new(events: Vec<MeasurementEvent>) -> Self {
        BootEventLog { events }
    }

    /// Citadel-internal serialization (Phase A wire form on the evidence).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("event log is serializable")
    }

    /// Decode a log produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Replay the log for one bank: fold each PCR's events in order. A
    /// `NoAction` event sets the PCR base; every other event extends it from
    /// the running value (zero if none yet).
    pub fn replay(&self, bank: &str) -> anyhow::Result<BTreeMap<u32, Vec<u8>>> {
        let size = bank_digest_size(bank)?;
        let mut pcrs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for ev in &self.events {
            let Some(digest) = ev.digest_for(bank) else {
                continue; // no digest for this bank in this event
            };
            match ev.event_type {
                EventType::NoAction => {
                    pcrs.insert(ev.pcr, digest.to_vec());
                }
                _ => {
                    let current = pcrs.entry(ev.pcr).or_insert_with(|| vec![0u8; size]);
                    *current = pcr_fold(bank, current, digest)?;
                }
            }
        }
        Ok(pcrs)
    }

    /// Does replaying this log reproduce every quoted PCR value? This is the
    /// integrity gate: `replay(log) == quote`.
    pub fn explains(&self, quoted: &[PcrValue]) -> bool {
        let mut by_bank: BTreeMap<&str, Vec<&PcrValue>> = BTreeMap::new();
        for q in quoted {
            by_bank.entry(q.bank.as_str()).or_default().push(q);
        }
        for (bank, qs) in by_bank {
            let replay = match self.replay(bank) {
                Ok(r) => r,
                Err(_) => return false,
            };
            for q in qs {
                match replay.get(&q.index) {
                    Some(d) if d.as_slice() == q.digest.as_slice() => {}
                    _ => return false,
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::hash_for_bank;

    fn extend_event(pcr: u32, raw: &[u8]) -> MeasurementEvent {
        // The measured digest is H(raw) for the bank, as TPM2_PCR_Extend takes
        // an already-hashed measurement.
        let digest = hash_for_bank("sha256", raw).unwrap();
        MeasurementEvent {
            pcr,
            event_type: EventType::Extend,
            digests: vec![("sha256".into(), digest)],
            data: raw.to_vec(),
        }
    }

    fn base_event(pcr: u32, value: Vec<u8>) -> MeasurementEvent {
        MeasurementEvent {
            pcr,
            event_type: EventType::NoAction,
            digests: vec![("sha256".into(), value)],
            data: vec![],
        }
    }

    fn pv(pcr: u32, digest: Vec<u8>) -> PcrValue {
        PcrValue { bank: "sha256".into(), index: pcr, digest }
    }

    #[test]
    fn replay_folds_from_zero() {
        let log = BootEventLog::new(vec![extend_event(4, b"kernel"), extend_event(4, b"initrd")]);
        let r = log.replay("sha256").unwrap();
        // PCR4 = fold(fold(0, H(kernel)), H(initrd))
        let size = bank_digest_size("sha256").unwrap();
        let step1 = pcr_fold("sha256", &vec![0u8; size], &hash_for_bank("sha256", b"kernel").unwrap()).unwrap();
        let step2 = pcr_fold("sha256", &step1, &hash_for_bank("sha256", b"initrd").unwrap()).unwrap();
        assert_eq!(r.get(&4).unwrap(), &step2);
    }

    #[test]
    fn no_action_sets_a_nonzero_base() {
        let base = vec![7u8; 32];
        let log = BootEventLog::new(vec![base_event(0, base.clone()), extend_event(0, b"x")]);
        let r = log.replay("sha256").unwrap();
        let expected = pcr_fold("sha256", &base, &hash_for_bank("sha256", b"x").unwrap()).unwrap();
        assert_eq!(r.get(&0).unwrap(), &expected);
    }

    #[test]
    fn explains_accepts_a_matching_quote_and_rejects_tamper() {
        let log = BootEventLog::new(vec![extend_event(4, b"kernel")]);
        let replayed = log.replay("sha256").unwrap().get(&4).unwrap().clone();
        assert!(log.explains(&[pv(4, replayed.clone())]));
        // Wrong quoted value → not explained.
        assert!(!log.explains(&[pv(4, vec![0xFF; 32])]));
        // A quoted PCR the log never touched → not explained.
        assert!(!log.explains(&[pv(9, vec![0u8; 32])]));
    }

    #[test]
    fn roundtrips_through_bytes() {
        let log = BootEventLog::new(vec![base_event(0, vec![1u8; 32]), extend_event(4, b"k")]);
        let back = BootEventLog::from_bytes(&log.to_bytes()).unwrap();
        assert_eq!(log, back);
    }

    #[test]
    fn garbage_bytes_fail_to_decode() {
        assert!(BootEventLog::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
    }
}
