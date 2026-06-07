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

/// The replay effect of a measured-boot event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// *Sets* the PCR's base value rather than extending it — for a PCR whose
    /// firmware base is non-zero (the TCG `StartupLocality` pattern). A
    /// Citadel-internal convention, not a TCG event type.
    Base,
    /// A normal measurement that extends its PCR.
    Extend,
    /// TCG `EV_NO_ACTION` (0x03): informational, **no PCR effect** — the Spec ID
    /// header, StartupLocality marker, etc.
    NoAction,
    /// A TCG `EV_*` type carried by its number; treated as `Extend` for replay.
    Unknown(u32),
}

/// Common TCG event-type numbers (`EV_*`), enough to classify the boot chain.
pub mod ev {
    pub const NO_ACTION: u32 = 0x0000_0003;
    pub const SEPARATOR: u32 = 0x0000_0004;
    pub const EVENT_TAG: u32 = 0x0000_0006;
    pub const IPL: u32 = 0x0000_000D; // boot loader / kernel cmdline (loader-specific)
    pub const EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001; // Secure Boot db/dbx/KEK/PK
    pub const EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003; // a loaded image (shim/grub/kernel)
    pub const EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0; // the cert that authorized an image
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
        self.digests
            .iter()
            .find(|(b, _)| b == bank)
            .map(|(_, d)| d.as_slice())
    }

    /// The measured digest extended for `bank` (the bytes folded into the PCR).
    pub fn measured_digest(&self, bank: &str) -> Option<&[u8]> {
        self.digest_for(bank)
    }

    /// Whether this event's `data` is **bound** to its measured digest — i.e.
    /// the digest is exactly `H(data)` for `bank`. Event data is otherwise not
    /// PCR-bound (design §3); only when this holds may a verifier trust the data
    /// (e.g. a cmdline string) as authentic. Exact-bytes; platform-specific
    /// normalization (trailing NUL, UTF-16) is follow-up.
    pub fn data_is_measured(&self, bank: &str) -> bool {
        match (
            self.digest_for(bank),
            crate::backend::hash_for_bank(bank, &self.data),
        ) {
            (Some(d), Ok(h)) => d == h.as_slice(),
            _ => false,
        }
    }

    /// The TCG event-type number, if this event came from a TCG log
    /// (`NoAction` → 0x03, `Unknown(n)` → n). `Base`/`Extend` are
    /// Citadel-internal and have none.
    pub fn tcg_type(&self) -> Option<u32> {
        match self.event_type {
            EventType::NoAction => Some(ev::NO_ACTION),
            EventType::Unknown(n) => Some(n),
            EventType::Base | EventType::Extend => None,
        }
    }

    /// The event data interpreted as a UTF-8 string (lossy) — e.g. an `EV_IPL`
    /// kernel command line. NOTE: event data is *not* PCR-bound (only the digest
    /// is), so trust it only as far as it is reflected in the measured digest.
    pub fn data_utf8(&self) -> String {
        String::from_utf8_lossy(&self.data)
            .trim_end_matches('\u{0}')
            .to_string()
    }

    /// Recover the **digest-bound** text payload of this event, or `None` if the
    /// data can't be reconciled with the measured digest.
    ///
    /// `data_is_measured` requires `digest == H(data)` exactly, but real
    /// firmware logs the *payload* differently from what it hashes. Observed on
    /// GRUB measured boot (Ubuntu/OVMF corpus): the logged `data` is
    /// `"<label>: <payload>"` (e.g. `"kernel_cmdline: /vmlinuz-… root=…"`,
    /// `"grub_cmd: …"`) while the PCR digest is `H(<payload>)` — sometimes with
    /// a trailing NUL. This tries those normalizations and returns the first
    /// whose hash matches the digest, so a verifier can trust the recovered
    /// string (cmdline, image path) as authentic. Returns the canonical payload
    /// (label stripped, no trailing NUL).
    pub fn measured_text(&self, bank: &str) -> Option<String> {
        let digest = self.digest_for(bank)?;
        let matches = |bytes: &[u8]| -> bool {
            crate::backend::hash_for_bank(bank, bytes)
                .map(|h| h.as_slice() == digest)
                .unwrap_or(false)
        };
        // Candidate payloads, in order of specificity. For each we test both the
        // bytes as-is and with a single trailing NUL appended (GRUB hashes the
        // C string including its terminator on some paths).
        let full = self.data.as_slice();
        let no_nul = full.strip_suffix(b"\0").unwrap_or(full);
        // GRUB descriptive label: everything after the first ": ".
        let after_label: &[u8] = full
            .windows(2)
            .position(|w| w == b": ")
            .map(|i| &full[i + 2..])
            .unwrap_or(full);
        let after_label = after_label.strip_suffix(b"\0").unwrap_or(after_label);
        for cand in [no_nul, after_label] {
            if matches(cand) {
                return Some(
                    String::from_utf8_lossy(cand)
                        .trim_end_matches('\u{0}')
                        .to_string(),
                );
            }
            let mut with_nul = cand.to_vec();
            with_nul.push(0);
            if matches(&with_nul) {
                return Some(
                    String::from_utf8_lossy(cand)
                        .trim_end_matches('\u{0}')
                        .to_string(),
                );
            }
        }
        None
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

    /// Decode an event log. Auto-detects the wire form: the Citadel-internal
    /// JSON produced by [`Self::to_bytes`], or a raw TCG `binary_bios_
    /// measurements` log (crypto-agile `TCG_PCR_EVENT2`), so evidence may carry
    /// exactly what the platform produced.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        match bytes.first() {
            Some(b'{') => Ok(serde_json::from_slice(bytes)?),
            _ => Self::parse_tcg(bytes),
        }
    }

    /// Replay the log for one bank: fold each PCR's events in order. `Base`
    /// sets the PCR's starting value; `NoAction` has no effect; every other
    /// event extends from the running value (zero if none yet).
    pub fn replay(&self, bank: &str) -> anyhow::Result<BTreeMap<u32, Vec<u8>>> {
        let size = bank_digest_size(bank)?;
        let mut pcrs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for ev in &self.events {
            if ev.event_type == EventType::NoAction {
                continue; // informational — no PCR effect
            }
            let Some(digest) = ev.digest_for(bank) else {
                continue; // no digest for this bank in this event
            };
            match ev.event_type {
                EventType::Base => {
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

    /// Events recorded for one PCR, in order.
    pub fn events_for_pcr(&self, pcr: u32) -> impl Iterator<Item = &MeasurementEvent> {
        self.events.iter().filter(move |e| e.pcr == pcr)
    }

    /// Events of a given TCG type (e.g. [`ev::EFI_BOOT_SERVICES_APPLICATION`]).
    pub fn events_of_type(&self, tcg_type: u32) -> impl Iterator<Item = &MeasurementEvent> {
        self.events
            .iter()
            .filter(move |e| e.tcg_type() == Some(tcg_type))
    }

    /// Whether some event for `pcr` measured exactly `digest` in `bank` — used
    /// to confirm an app/runtime measurement was actually folded into a PCR
    /// (e.g. an IMA measurement into PCR 10), the binding behind a verified
    /// `pcr_bound` claim (`application-appraisal.md` P4).
    pub fn contains_measurement(&self, pcr: u32, digest: &[u8], bank: &str) -> bool {
        self.events
            .iter()
            .any(|e| e.pcr == pcr && e.digest_for(bank) == Some(digest))
    }

    /// Parse a raw TCG `binary_bios_measurements` log (crypto-agile format):
    /// a legacy `TCG_PCR_EVENT` header carrying the Spec ID Event (which
    /// declares the digest algorithms and sizes), followed by `TCG_PCR_EVENT2`
    /// records. Returns an error on malformed input rather than panicking.
    pub fn parse_tcg(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        let mut events = Vec::new();

        // --- legacy header record (TCG_PCR_EVENT, SHA-1) ---
        let pcr0 = r.u32()?;
        let etype0 = r.u32()?;
        let sha1 = r.take(20)?.to_vec();
        let spec_len = r.u32()? as usize;
        let spec = r.take(spec_len)?;
        let alg_sizes = parse_spec_id_algorithms(spec)?;
        events.push(MeasurementEvent {
            pcr: pcr0,
            event_type: tcg_event_type(etype0),
            digests: vec![("sha1".to_string(), sha1)],
            data: spec.to_vec(),
        });

        // --- crypto-agile records (TCG_PCR_EVENT2) ---
        while r.remaining() >= 8 {
            let pcr = r.u32()?;
            // Firmware often pads the allocated log region after the last real
            // event; a `pcrIndex` of 0xFFFFFFFF (or an all-zero tail) is the
            // conventional terminator — stop rather than mis-parse padding.
            if pcr == 0xFFFF_FFFF {
                break;
            }
            let etype = r.u32()?;
            let count = r.u32()? as usize;
            // A sane log has a small digest count; a huge value is padding/
            // corruption, not a real record — stop cleanly.
            if count > 16 {
                break;
            }
            let mut digests = Vec::with_capacity(count);
            for _ in 0..count {
                let alg_id = r.u16()?;
                let size = alg_sizes
                    .get(&alg_id)
                    .copied()
                    .or_else(|| known_digest_size(alg_id))
                    .ok_or_else(|| anyhow::anyhow!("unknown TPM alg id {alg_id:#06x}"))?;
                let digest = r.take(size)?.to_vec();
                digests.push((bank_name(alg_id), digest));
            }
            let data_len = r.u32()? as usize;
            let data = r.take(data_len)?.to_vec();
            events.push(MeasurementEvent {
                pcr,
                event_type: tcg_event_type(etype),
                digests,
                data,
            });
        }

        Ok(BootEventLog { events })
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

/// Map a TCG event-type number to our replay-effect enum.
fn tcg_event_type(n: u32) -> EventType {
    if n == ev::NO_ACTION {
        EventType::NoAction
    } else {
        EventType::Unknown(n)
    }
}

/// TPM2 algorithm-id → Citadel bank name.
fn bank_name(alg_id: u16) -> String {
    match alg_id {
        0x0004 => "sha1".to_string(),
        0x000B => "sha256".to_string(),
        0x000C => "sha384".to_string(),
        0x000D => "sha512".to_string(),
        0x0012 => "sm3_256".to_string(),
        other => format!("alg-{other:#06x}"),
    }
}

/// Known digest size for a TPM2 algorithm id (fallback when the Spec ID Event
/// does not list it).
fn known_digest_size(alg_id: u16) -> Option<usize> {
    match alg_id {
        0x0004 => Some(20),
        0x000B => Some(32),
        0x000C => Some(48),
        0x000D => Some(64),
        0x0012 => Some(32),
        _ => None,
    }
}

/// Parse the `(algorithmId → digestSize)` table out of a Spec ID Event03
/// structure (the data field of the legacy header record).
fn parse_spec_id_algorithms(spec: &[u8]) -> anyhow::Result<BTreeMap<u16, usize>> {
    let mut r = Reader::new(spec);
    let sig = r.take(16)?;
    if &sig[..15] != b"Spec ID Event03" {
        anyhow::bail!("not a Spec ID Event03 header");
    }
    let _platform_class = r.u32()?;
    let _spec_minor = r.u8()?;
    let _spec_major = r.u8()?;
    let _spec_errata = r.u8()?;
    let _uintn_size = r.u8()?;
    let count = r.u32()? as usize;
    let mut sizes = BTreeMap::new();
    for _ in 0..count {
        let alg_id = r.u16()?;
        let size = r.u16()? as usize;
        sizes.insert(alg_id, size);
    }
    Ok(sizes)
}

/// A little-endian, bounds-checked byte reader (errors instead of panicking on
/// malformed/truncated logs).
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| anyhow::anyhow!("event log truncated at {}", self.pos))?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> anyhow::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> anyhow::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
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
            event_type: EventType::Base,
            digests: vec![("sha256".into(), value)],
            data: vec![],
        }
    }

    fn pv(pcr: u32, digest: Vec<u8>) -> PcrValue {
        PcrValue {
            bank: "sha256".into(),
            index: pcr,
            digest,
        }
    }

    #[test]
    fn replay_folds_from_zero() {
        let log = BootEventLog::new(vec![extend_event(4, b"kernel"), extend_event(4, b"initrd")]);
        let r = log.replay("sha256").unwrap();
        // PCR4 = fold(fold(0, H(kernel)), H(initrd))
        let size = bank_digest_size("sha256").unwrap();
        let step1 = pcr_fold(
            "sha256",
            &vec![0u8; size],
            &hash_for_bank("sha256", b"kernel").unwrap(),
        )
        .unwrap();
        let step2 = pcr_fold(
            "sha256",
            &step1,
            &hash_for_bank("sha256", b"initrd").unwrap(),
        )
        .unwrap();
        assert_eq!(r.get(&4).unwrap(), &step2);
    }

    #[test]
    fn base_event_sets_a_nonzero_base() {
        let base = vec![7u8; 32];
        let log = BootEventLog::new(vec![base_event(0, base.clone()), extend_event(0, b"x")]);
        let r = log.replay("sha256").unwrap();
        let expected = pcr_fold("sha256", &base, &hash_for_bank("sha256", b"x").unwrap()).unwrap();
        assert_eq!(r.get(&0).unwrap(), &expected);
    }

    #[test]
    fn no_action_event_has_no_pcr_effect() {
        // An EV_NO_ACTION between two extends must not change the PCR.
        let noact = MeasurementEvent {
            pcr: 4,
            event_type: EventType::NoAction,
            digests: vec![("sha256".into(), vec![0u8; 32])],
            data: vec![],
        };
        let with = BootEventLog::new(vec![extend_event(4, b"a"), noact, extend_event(4, b"b")]);
        let without = BootEventLog::new(vec![extend_event(4, b"a"), extend_event(4, b"b")]);
        assert_eq!(
            with.replay("sha256").unwrap(),
            without.replay("sha256").unwrap()
        );
    }

    // --- TCG binary parsing (Phase B) ---

    /// Build a minimal crypto-agile TCG log: a Spec ID header declaring sha256,
    /// then one EVENT2 record per `(pcr, event_type, sha256-digest, data)`.
    fn tcg_bytes(records: &[(u32, u32, [u8; 32], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        // legacy header: pcr0, EV_NO_ACTION, 20-byte sha1 (zero), specSize, spec
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&ev::NO_ACTION.to_le_bytes());
        out.extend_from_slice(&[0u8; 20]);
        let mut spec = Vec::new();
        spec.extend_from_slice(b"Spec ID Event03\0"); // 16 bytes
        spec.extend_from_slice(&0u32.to_le_bytes()); // platformClass
        spec.push(0); // minor
        spec.push(2); // major
        spec.push(0); // errata
        spec.push(2); // uintnSize
        spec.extend_from_slice(&1u32.to_le_bytes()); // numberOfAlgorithms
        spec.extend_from_slice(&0x000Bu16.to_le_bytes()); // sha256
        spec.extend_from_slice(&32u16.to_le_bytes()); // size
        spec.push(0); // vendorInfoSize
        out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        out.extend_from_slice(&spec);
        // EVENT2 records
        for (pcr, etype, digest, data) in records {
            out.extend_from_slice(&pcr.to_le_bytes());
            out.extend_from_slice(&etype.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes()); // digest count
            out.extend_from_slice(&0x000Bu16.to_le_bytes()); // sha256
            out.extend_from_slice(digest);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn parses_tcg_binary_and_replays() {
        let d_kernel = hash_for_bank("sha256", b"kernel").unwrap();
        let d_cmdline = hash_for_bank("sha256", b"root=/dev/sda1 ro").unwrap();
        let raw = tcg_bytes(&[
            (
                4,
                ev::EFI_BOOT_SERVICES_APPLICATION,
                d_kernel.clone().try_into().unwrap(),
                b"\\kernel.efi",
            ),
            (
                8,
                ev::IPL,
                d_cmdline.try_into().unwrap(),
                b"root=/dev/sda1 ro",
            ),
        ]);
        let log = BootEventLog::parse_tcg(&raw).unwrap();

        // header + 2 records.
        assert_eq!(log.events.len(), 3);
        // Replay reproduces the folded PCRs (header is EV_NO_ACTION → no effect).
        let r = log.replay("sha256").unwrap();
        let pcr4 = pcr_fold("sha256", &[0u8; 32], &d_kernel).unwrap();
        assert_eq!(r.get(&4).unwrap(), &pcr4);
        // Classification + cmdline extraction.
        let ipl: Vec<_> = log.events_of_type(ev::IPL).collect();
        assert_eq!(ipl.len(), 1);
        assert_eq!(ipl[0].data_utf8(), "root=/dev/sda1 ro");
        assert_eq!(
            log.events_of_type(ev::EFI_BOOT_SERVICES_APPLICATION)
                .count(),
            1
        );
    }

    #[test]
    fn from_bytes_dispatches_tcg_vs_json() {
        // JSON path.
        let json = BootEventLog::new(vec![extend_event(4, b"k")]).to_bytes();
        assert_eq!(BootEventLog::from_bytes(&json).unwrap().events.len(), 1);
        // TCG path.
        let d = hash_for_bank("sha256", b"k").unwrap();
        let raw = tcg_bytes(&[(4, ev::IPL, d.try_into().unwrap(), b"")]);
        assert_eq!(BootEventLog::from_bytes(&raw).unwrap().events.len(), 2);
    }

    #[test]
    fn measured_text_recovers_grub_label_prefixed_payload() {
        // GRUB logs "<label>: <payload>" but measures only <payload> (observed
        // on the real OVMF corpus). measured_text must recover <payload>.
        let payload = b"/vmlinuz-6.8.0-117-generic root=LABEL=cloudimg-rootfs ro";
        let digest = hash_for_bank("sha256", payload).unwrap();
        let mut data = b"kernel_cmdline: ".to_vec();
        data.extend_from_slice(payload);
        let ev = MeasurementEvent {
            pcr: 8,
            event_type: EventType::Unknown(ev::IPL),
            digests: vec![("sha256".into(), digest)],
            data,
        };
        // data_is_measured (exact bytes) does NOT hold — the label isn't hashed.
        assert!(!ev.data_is_measured("sha256"));
        // measured_text reconciles it to the digest-bound payload.
        assert_eq!(
            ev.measured_text("sha256").as_deref(),
            Some(payload).map(|p| std::str::from_utf8(p).unwrap())
        );

        // And the trailing-NUL convention: digest = H(payload || 0).
        let mut with_nul = payload.to_vec();
        with_nul.push(0);
        let nul_digest = hash_for_bank("sha256", &with_nul).unwrap();
        let ev2 = MeasurementEvent {
            pcr: 9,
            event_type: EventType::Unknown(ev::IPL),
            digests: vec![("sha256".into(), nul_digest)],
            data: payload.to_vec(),
        };
        assert_eq!(
            ev2.measured_text("sha256").as_deref(),
            Some(std::str::from_utf8(payload).unwrap())
        );

        // A digest bound to nothing in the data is not recovered.
        let ev3 = MeasurementEvent {
            pcr: 8,
            event_type: EventType::Unknown(ev::IPL),
            digests: vec![("sha256".into(), vec![0u8; 32])],
            data: b"kernel_cmdline: /vmlinuz-x".to_vec(),
        };
        assert_eq!(ev3.measured_text("sha256"), None);
    }

    #[test]
    fn multibank_record_replays_the_sha256_bank() {
        // Real OVMF logs are crypto-agile: each EVENT2 carries both a sha1 and
        // a sha256 digest. Replay over sha256 must use the sha256 digest.
        let d256 = hash_for_bank("sha256", b"shim").unwrap();
        let d1 = vec![0xAAu8; 20]; // arbitrary sha1 (different value)
        let mut out = tcg_header_two_banks();
        // EVENT2: pcr 4, EV_EFI_BOOT_SERVICES_APPLICATION, {sha1, sha256}, data
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&ev::EFI_BOOT_SERVICES_APPLICATION.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes()); // 2 digests
        out.extend_from_slice(&0x0004u16.to_le_bytes()); // sha1
        out.extend_from_slice(&d1);
        out.extend_from_slice(&0x000Bu16.to_le_bytes()); // sha256
        out.extend_from_slice(&d256);
        out.extend_from_slice(&0u32.to_le_bytes()); // data_len

        let log = BootEventLog::parse_tcg(&out).unwrap();
        let r256 = log.replay("sha256").unwrap();
        let expected = pcr_fold("sha256", &[0u8; 32], &d256).unwrap();
        assert_eq!(
            r256.get(&4).unwrap(),
            &expected,
            "sha256 replay uses sha256 digest"
        );
        assert!(log.contains_measurement(4, &d256, "sha256"));
    }

    #[test]
    fn trailing_padding_is_ignored() {
        // A real allocated log region is padded after the last event; a
        // 0xFFFFFFFF pcrIndex terminator (and zero padding) must not derail
        // parsing or replay.
        let d = hash_for_bank("sha256", b"k").unwrap();
        let mut out = tcg_bytes(&[(4, ev::IPL, d.clone().try_into().unwrap(), b"")]);
        // terminator + junk padding
        out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        out.extend_from_slice(&[0u8; 64]);
        let log = BootEventLog::parse_tcg(&out).unwrap();
        // header + the one real event; padding dropped.
        assert_eq!(log.events.len(), 2);
        assert_eq!(
            log.replay("sha256").unwrap().get(&4).unwrap(),
            &pcr_fold("sha256", &[0u8; 32], &d).unwrap()
        );
    }

    /// A crypto-agile header declaring BOTH sha1 and sha256 (like real OVMF).
    fn tcg_header_two_banks() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&ev::NO_ACTION.to_le_bytes());
        out.extend_from_slice(&[0u8; 20]);
        let mut spec = Vec::new();
        spec.extend_from_slice(b"Spec ID Event03\0");
        spec.extend_from_slice(&0u32.to_le_bytes());
        spec.push(0);
        spec.push(2);
        spec.push(0);
        spec.push(2);
        spec.extend_from_slice(&2u32.to_le_bytes()); // 2 algorithms
        spec.extend_from_slice(&0x0004u16.to_le_bytes()); // sha1
        spec.extend_from_slice(&20u16.to_le_bytes());
        spec.extend_from_slice(&0x000Bu16.to_le_bytes()); // sha256
        spec.extend_from_slice(&32u16.to_le_bytes());
        spec.push(0);
        out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        out.extend_from_slice(&spec);
        out
    }

    #[test]
    fn truncated_tcg_log_errors_without_panic() {
        let d = hash_for_bank("sha256", b"k").unwrap();
        let mut raw = tcg_bytes(&[(4, ev::IPL, d.try_into().unwrap(), b"data")]);
        raw.truncate(raw.len() - 3); // chop the tail
        assert!(BootEventLog::parse_tcg(&raw).is_err());
        // And a header-only / garbage buffer.
        assert!(BootEventLog::parse_tcg(&[0x01, 0x02]).is_err());
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
