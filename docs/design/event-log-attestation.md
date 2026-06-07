# Citadel: Event-Log Ingestion & Semantic Validation

Document Version: 0.2
Status: Phase A (replay / integrity) **built**; Phases B–D planned
Project: Citadel
Audience: Architecture, Security, Platform, Runtime Engineers
Related: `measured-state-transitions.md`, `distributed-log-shipping-lthash.md`,
`distributed-attestation-mesh.md`, `mma-upgrade.md`

> Unblocks **Layer 4 §10.4** of `measured-state-transitions.md` (event-log
> semantic validation) and fills the **§5/§6 gap** of
> `distributed-log-shipping-lthash.md` (real event sources / canonical event
> format). Today Citadel appraises the *quote* (the final PCR vector) only;
> this design adds ingestion, transport, replay, and semantic appraisal of the
> **event log that produced those PCRs**. It is a self-contained sub-project
> that starts at the `tpm_core::backend::TpmBackend` seam.

---

## 1. Problem & scope

PCRs are lossy accumulators: `PCR = extend(extend(extend(0, m1), m2), …)`. They
prove *that* a sequence of measurements happened, but not *what* each one was.
Every prior layer therefore reasons about opaque digests:

* Layer 1–3 accept a digest because it is enumerated / signed / provenanced.
* `PcrClass::Semantic` indices (kernel, initramfs, cmdline, bootloader) are
  currently **value-unchecked** — explicitly deferred to "event-log policy".

This design provides that policy. It lets a verifier answer questions the quote
alone cannot: *was the bootloader signed by a trusted key? is the kernel command
line free of `init=/bin/sh`? is this the initramfs the approved pipeline built?*

**In scope:** ingest the TCG measured-boot event log (and later IMA), carry it
with the evidence, **replay** it against the quote, and appraise the individual
events under policy. **Out of scope (separate efforts):** the firmware/OS
plumbing that produces the logs, and confidential-computing launch evidence
(SEV-SNP/TDX) — though the appraisal shape generalises to them.

---

## 2. Background: the logs

**TCG measured-boot event log.** A firmware-produced, append-only list of
events; each event extends a digest into a PCR. Sources:

* Linux: `/sys/kernel/security/tpm0/binary_bios_measurements`
* UEFI: the TCG2 protocol `GetEventLog`
* Windows: Measured Boot / TBS APIs

Two wire formats: the legacy `TCG_PCR_EVENT` (SHA-1 only) and the crypto-agile
`TCG_PCR_EVENT2` (TPM 2.0; multiple digests per event, a digest per active PCR
bank). An event carries `(pcr_index, event_type, digests[], event_data)`.

**IMA runtime measurement log.** Linux Integrity Measurement Architecture
(`/sys/kernel/security/ima/binary_runtime_measurements`) extends PCR 10 with a
measurement per file as it is loaded — runtime, post-boot, ongoing. Same
replay/appraise shape; addressed in a later phase.

---

## 3. The core invariant — and its limits

The single load-bearing check:

```
replay(event_log) == quoted_PCRs
```

For each PCR the log touches, fold its events' digests in order and require the
result to equal the TPM-signed quoted value. Because PCR extension is a
hash-chain over preimage-resistant digests, an attacker **cannot** fabricate,
reorder, omit, or pad a log that still replays to a genuine quoted vector. So
replay success means: *this log is the authentic, complete explanation of the
quote.* Failure → `EVENT_LOG_INCONSISTENT`; absent log → `EVENT_LOG_MISSING`
(both reason codes already exist in `types.rs`, as placeholders this fills).

**The limit that shapes everything downstream:** only the **digest** of each
event is extended into the PCR. The human-readable `event_data` (file paths,
version strings, cmdline text) is *not* cryptographically bound unless it is
itself part of the hashed measurement. Therefore:

* You may trust event **digests** and their **order** absolutely.
* You may trust event **data** only to the extent it is reflected in the digest
  (e.g. EV_EFI_VARIABLE events whose digest is over the variable contents, or a
  cmdline whose digest is over the exact string).

This means semantic identity (publisher / version / channel) generally still
needs a **mapping from digest → identity**, which comes from a signed source —
i.e. this composes with Layer 3 manifests (§7), it does not replace them.

---

## 4. Architecture

```text
attester                                    verifier
────────                                    ────────
TpmBackend::read_event_log()  ─┐
                               │  AttestationEvidence { quote, event_log, … }
quote (PCR vector, signed) ────┘ ───────────────────────────────►  1. verify quote sig + nonce   (existing)
                                                                    2. replay(event_log)==quote   (NEW, §3)
                                                                    3. map events → artifacts     (NEW, §6)
                                                                    4. appraise events under
                                                                       per-PCR / fleet policy     (NEW, §6/§7)
                                                                            ▼
                                                                    Pass / Warn / Fail
                                                                    (+ EVENT_LOG_* reasons)
```

* **Ingestion** — the attester reads its event log when answering a challenge
  and attaches it to the evidence. New `TpmBackend` method `read_event_log()`.
* **Transport** — the log rides in `AttestationEvidence`. Logs are typically a
  few KB–tens of KB; for large/IMA logs, ship a hash and let the verifier pull
  on demand (mirrors the LtHash pull in `logship.rs`). First cut: attach inline.
* **Replay + appraisal** — verifier-side, in a new `eventlog` module, invoked
  from `attest.rs::verify` for `Semantic`-class indices.

---

## 5. Data model (`crates/citadel-mesh/src/eventlog.rs`)

```rust
/// One parsed measured-boot event (TCG_PCR_EVENT2-shaped).
pub struct MeasurementEvent {
    pub pcr: u32,
    pub event_type: EventType,          // EV_* (enum + Unknown(u32))
    pub digests: Vec<(Algorithm, Vec<u8>)>,  // one per bank
    pub event_data: Vec<u8>,            // opaque; NOT PCR-bound (see §3)
}

/// A parsed measured-boot log (name avoids clashing with logship::EventLog).
pub struct BootEventLog { pub events: Vec<MeasurementEvent> }

impl BootEventLog {
    pub fn parse(raw: &[u8]) -> anyhow::Result<Self>;            // TCG format(s)
    /// Fold the events of `bank` into per-PCR digests.
    pub fn replay(&self, bank: Algorithm) -> BTreeMap<u32, Vec<u8>>;
    /// Does the replay match the quoted PCR values?
    pub fn explains(&self, quoted: &[PcrValue]) -> bool;
}
```

`AttestationEvidence` gains `#[serde(default)] pub event_log: Option<Vec<u8>>`
(raw bytes, byte-identical when absent so v1 evidence is unaffected).

---

## 6. Integration with the existing engine

* **`TpmBackend`** — add `read_event_log(&self) -> anyhow::Result<Option<Vec<u8>>>`.
  `MockBackend` synthesises a log whose events replay to its mock PCR values, so
  the whole path is **deterministically testable in-process** (like the rest of
  the mesh) before any hardware. The vTPM / real backends return the platform
  log.
* **`reference::PcrClass::Semantic`** — today value-unchecked. With an event
  log present, a `Semantic` index is appraised by event-log policy instead;
  without one, it falls back to today's behaviour (still value-unchecked, or
  `EVENT_LOG_MISSING` if policy requires a log — configurable).
* **`attest.rs::verify`** — after the quote/nonce check, if any selected index
  is `Semantic`: require `event_log.explains(quote)` (else `EVENT_LOG_*` hard
  fail), then run §6 artifact extraction + policy.
* **`ArtifactIdentity` / `FleetArtifactPolicy`** (Layer 3) — reused as the
  policy vocabulary; the difference is the artifact is now *derived from the
  event log* (and a signed digest→identity mapping) rather than asserted.

**Event → artifact extraction** is the firmware-variant-heavy part: recognise
the bootloader/kernel/initramfs/cmdline events by `(pcr, event_type)` and parse
their data (e.g. `EV_EFI_BOOT_SERVICES_APPLICATION`, IPL events, the cmdline
event). This is inherently messy and is its own phase.

---

## 7. Establishing semantic identity (composition with Layer 3)

Because event *data* isn't PCR-bound (§3), "this digest is kernel 6.8.0 from the
prod channel" must come from a trusted mapping, two complementary ways:

1. **Signed reference mapping** — a Layer-3 `ReferenceManifest` maps a measured
   digest to its `ArtifactIdentity`. Replay proves the digest was measured; the
   manifest names it; fleet policy judges it. (Replay + Layer 3.)
2. **Embedded-signature verification** — for Secure Boot, the log records the
   signing certificate used to validate a loaded image; the verifier checks that
   cert chains to an accepted db key (reusing `EndorserCert` chain-to-anchor).
   This yields publisher identity *without* enumerating every binary hash.

Both land in the same `FleetArtifactPolicy` vocabulary (channel / baseline /
denylist). Cmdline policy (`require`/`deny` tokens) is evaluated against the
cmdline event **only when** its digest matches the measured value.

---

## 8. Threat-model additions

* **Forged/garbled log** → fails replay (§3) → `EVENT_LOG_INCONSISTENT`.
* **Omitted/replayed events** → cannot replay to a genuine quote (§3).
* **Lying event data** → never trusted beyond the digest; semantic identity
  comes from signed mappings or embedded-sig verification (§7).
* **Log/quote mismatch from sampling skew** (log read at a different time than
  the quote) → bounded by reading both in the same challenge response; replay
  catches any divergence.
* **Still out of scope:** TPM physical extraction; pre-first-measurement
  supply-chain (unchanged from the mesh threat model).

---

## 9. Phasing

* **Phase A — replay (integrity). ✅ Built.** `tpm_core::eventlog`
  (`BootEventLog`/`MeasurementEvent`/`EventType`, `replay`/`explains`,
  `to_bytes`/`from_bytes`); `TpmBackend::read_event_log` (default `None`);
  `MockBackend` records extends and synthesizes a log that replays to its PCRs;
  `AttestationEvidence.event_log`; `attest.rs::verify` enforces `replay==quote`
  for `Semantic` indices, filling `EVENT_LOG_MISSING`/`EVENT_LOG_INCONSISTENT`.
  Deterministically tested, no hardware. *(Module lives in `tpm-core`, not
  `citadel-mesh` as first sketched, so `MockBackend` can build the type without
  a dependency cycle.)* TCG **binary** parsing remains Phase B; Phase A uses the
  Citadel-internal `to_bytes` form.
* **Phase B — event→artifact extraction.** Parsers for the boot-chain event
  types; map events to `ArtifactIdentity`. Firmware-variant heavy; start with
  one reference platform (OVMF/UEFI + shim + GRUB + Linux).
* **Phase C — semantic policy.** Wire extracted artifacts into
  `FleetArtifactPolicy` (signed-mapping path first, then embedded-sig); cmdline
  require/deny; promote `Semantic` indices from value-unchecked to validated.
* **Phase D — IMA / runtime.** Ingest the IMA log (PCR 10); ongoing runtime
  attestation beyond boot; ties into the log-shipping pipeline.

Phases A and C are the security-meaningful milestones; B is the grind. A alone
is worth shipping (it proves the log explains the quote and closes the
`EVENT_LOG_*` placeholders).

---

## 10. Open questions & risks

* **Parser robustness / firmware variance** — real event logs are notoriously
  irregular; B is the main risk. Mitigate by starting on one reference platform
  and treating unrecognised events as opaque-but-replayable.
* **Log size & transport** — attach inline first; add a hash-and-pull path
  (reusing the logship pull) if logs (esp. IMA) get large.
* **Bank selection** — replay against the bank the quote used (`sha256`);
  reject SHA-1-only logs by policy.
* **Backend reach** — does the vTPM component expose a usable event log, or must
  Citadel synthesise one from its own measurements? Determines how realistic
  Phase A hardware testing can be before B.
* **Relationship to MMA** — MMA already measures Citadel's own binary into a
  PCR; its measurement could be emitted as an event-log entry so the same
  replay/appraise path covers the agent (PCR 14).

---

## 11. Relationship to other designs

* **`measured-state-transitions.md`** — this is the engine behind that doc's
  Layer 4 §10.4; `PcrClass::Semantic` and `FleetArtifactPolicy` are the seams.
* **`distributed-log-shipping-lthash.md`** — fills its §5 (event sources) and
  §6 (canonical event format); a parsed `MeasurementEvent` is the real input the
  LtHash log has been carrying abstractly via `append_event`.
* **`mma-upgrade.md`** — the agent self-measurement (PCR 14) becomes one more
  appraised event.
