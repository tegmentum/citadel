# Citadel: Attestation & Measured-State Roadmap

Status: Plan
Project: Citadel
Audience: Architecture, Security, Platform, Runtime Engineers
Related: `event-log-attestation.md`, `measured-state-transitions.md`,
`distributed-log-shipping-lthash.md`, `distributed-attestation-mesh.md`,
`mma-upgrade.md`, `mesh-integration-roadmap.md`

The measured-state / event-log appraisal stack is functionally complete in the
**network-free, deterministic** core (`tpm-core` + `citadel-mesh`): multi-value
appraisal, per-PCR class, signed manifests + revocation + audit + anti-entropy,
boot profiles + assignment + quorum promotion, event-log replay + TCG parsing +
semantic policy (cmdline + per-digest artifact) + Secure Boot db/dbx authority.
This roadmap scopes and orders **everything still outstanding** across the three
design docs, grounded in the current code seams.

Each item: **goal · scope · seam · test · effort · gating**. Effort is rough
calendar (1 engineer). "Gating" = needs real hardware/IO that the in-process
harness cannot provide.

| # | Item | Track | Effort | Gating |
|---|------|-------|--------|--------|
| A1 | Real-platform event-log corpus validation | Boot appraisal | 2–3 d | sample logs |
| A2 | X.509 / CA-chain authority validation | Boot appraisal | 1–1.5 wk | no |
| A3 | Structured `ArtifactIdentity` extraction from events | Boot appraisal | 1–2 wk | no |
| B1 | Real event-log ingestion (`/sys`, vTPM, HW) | Hardware bring-up | 1 wk | hardware/vTPM |
| B2 | Signed reference values from a real RVP | Hardware bring-up | 1 wk | build pipeline |
| C1 | IMA / runtime measurement (event-log Phase D) | Runtime | 2–3 wk | hardware (real) |
| D1 | Signed quote-bound checkpoints (log-ship §9–10) | Durability | ✅ done | no |
| D2 | On-disk persistence (log-ship §17) | Durability | 1–2 wk | no |
| D3 | Erasure placement as the default replication | Durability | ✅ done | no |
| E1 | Reference manifest flows over HTTP transport | Distribution | ✅ done | no |
| E2 | mTLS between agents via the TPM-held key | Distribution | 3–5 d | hardware |

---

## Track A — finish boot-appraisal (no new domain, mostly no hardware)

### A1 — Real-platform event-log corpus validation
* **Goal:** prove `parse_tcg` / `replay` against logs real firmware emits, not
  just hand-built ones. The robustness risk flagged in `event-log-attestation.md`.
* **Scope:** collect `binary_bios_measurements` from OVMF/EDK2 + shim + GRUB +
  Linux (via `swtpm`+QEMU, reproducible) and a couple of bare-metal samples;
  add them as test fixtures; assert parse-without-error and that replay matches
  the accompanying quoted PCRs. Harden the parser for the warts found (vendor
  `EV_EVENT_TAG`s, padded data, multi-bank logs, SHA-1-only legacy logs we
  reject by policy).
* **Seam:** `tpm_core::eventlog::parse_tcg`; a `tests/fixtures/` corpus.
* **Test:** golden parse+replay per fixture.
* **Effort:** 2–3 d. **Gating:** needs sample logs (swtpm/QEMU is enough — no
  physical TPM).

### A2 — X.509 / CA-chain authority validation
* **Goal:** the follow-up called out in the Secure Boot work — today an
  authority is matched as an **opaque blob** (faithful to *pinned* `db` certs).
  Real `db` often holds **CA** certs that authorize many leaf images; validating
  that requires X.509 chain building + signature verification.
* **Scope:** parse the `EV_EFI_VARIABLE_AUTHORITY` `EFI_SIGNATURE_DATA` to a
  cert; build/verify the chain to a `db` CA; honor `dbx` by cert hash/serial.
  Extend `FleetArtifactPolicy` so a trusted authority may be a CA, not only a
  pinned leaf.
* **Seam:** `FleetArtifactPolicy::authority_permits` (today byte-membership) →
  add a chain-validating path; new dep (`x509-cert` + `der`, or `webpki`).
* **Test:** synthetic CA → leaf chains; revoke via `dbx`; expired/wrong-EKU
  rejected. Deterministic, in-process.
* **Effort:** 1–1.5 wk (mostly the new dep + cert plumbing). **Gating:** none.
* **Risk:** pulling an X.509 stack into the dependency surface — keep it behind
  a feature flag so the core stays lean.

### A3 — Structured `ArtifactIdentity` extraction from events
* **Goal:** derive `(component, publisher, version)` **directly from the event
  log** instead of only from a signed digest→identity manifest — so policy can
  judge a never-before-seen build's version without a manifest naming it.
* **Scope:** parse `EV_EFI_BOOT_SERVICES_APPLICATION` device paths / PE-COFF
  version resources, GRUB/IPL strings, and the cmdline into `ArtifactIdentity`;
  feed them into the existing `FleetArtifactPolicy` (channel/baseline/denylist).
  Firmware-variant heavy — start with the A1 reference platform.
* **Seam:** new `eventlog` extractors → `ArtifactIdentity`; reuse
  `appraise_eventlog`.
* **Test:** extraction units over the A1 corpus; e2e version-baseline on an
  event-derived (un-manifested) kernel.
* **Effort:** 1–2 wk. **Gating:** none (uses A1 corpus). **Depends on A1.**

---

## Track B — run on real hardware (the "runs on a real machine" bridge)

### B1 — Real event-log ingestion
* **Goal:** `read_event_log` returns the *platform* log, not `MockBackend`'s
  synthetic one — closing the `distributed-log-shipping-lthash.md` §5 gap.
* **Scope:** implement `read_event_log` on the vTPM and hardware backends:
  read `/sys/kernel/security/tpm0/binary_bios_measurements` (Linux), the UEFI
  TCG2 `GetEventLog`, or the vTPM component's log; hand the raw bytes straight
  to `parse_tcg` (already format-detecting). Wire the same `MeasurementEvent`
  stream into the LtHash log (`logship::append_event`), filling §6.
* **Seam:** `TpmBackend::read_event_log` overrides in `vtpm-backend` / hardware.
* **Test:** vTPM acceptance test (like the existing real-vTPM attestation test);
  assert ingested-log replay == live quote.
* **Effort:** 1 wk. **Gating:** vTPM/hardware. **Depends on A1** (parser
  hardened against real logs first).

### B2 — Signed reference values from a real RVP
* **Goal:** production references come from a Reference Value Provider replaying
  approved builds, not test self-capture — closing the `set_peer_reference`
  bootstrap caveat in `measured-state-transitions.md` §5.
* **Scope:** a small RVP tool that, given an approved image, computes its
  expected PCRs / event digests and emits a signed `ReferenceManifest` (+
  `ArtifactIdentity`); operators ingest it via the existing manifest gossip.
* **Seam:** reuses `ReferenceManifest::issue_chained` and the manifest path —
  this is tooling around an existing API, not new mesh code.
* **Test:** RVP output adopted by a node; a matching build passes, a tampered
  one is `REFERENCE_UNKNOWN`.
* **Effort:** 1 wk. **Gating:** an approved-build pipeline to measure against.

---

## Track C — runtime measurement (new domain)

### C1 — IMA / runtime (event-log Phase D)
* **Goal:** attest measurements that happen *after* boot — file/exec integrity
  via Linux IMA (PCR 10), ongoing rather than one-shot.
* **Scope:** parse `binary_runtime_measurements` (`ima-ng`/`ima-sig`
  templates); a runtime appraisal policy (allowed file hashes / signing keys);
  feed the rolling log into the LtHash shipping pipeline so runtime evidence is
  reconciled and preserved like boot evidence; periodic re-quote of PCR 10.
* **Seam:** new IMA parser in `eventlog`; appraisal alongside `appraise_eventlog`;
  ties into `logship`. Likely a new PCR class behavior (append-only, growing).
* **Test:** IMA template parse units; e2e an unauthorized exec drives distrust.
* **Effort:** 2–3 wk. **Gating:** real Linux/IMA (synthetic templates get unit
  coverage, but meaningful validation needs a running kernel). Largest new
  surface; genuinely separate from boot appraisal.

---

## Track D — durability & subsystem unification (software, no hardware)

### D1 — Signed quote-bound checkpoints — ✅ DONE
* **Goal:** close `distributed-log-shipping-lthash.md` §9–10 — bind the LtHash
  log root to a TPM quote in a signed `Checkpoint`, unifying the two
  subsystems (today log-shipping and attestation don't touch).
* **Delivered:** `logship::Checkpoint` (mesh-signed, embeds a TPM quote whose
  nonce = `checkpoint_nonce(boot, window, root)`); `node::checkpoint_window` /
  `advertise_checkpoints` / `on_checkpoint` (verify sig + binding + quote;
  record per sealed `(node, boot, window)`); conflicting checkpoints retained as
  attributable `equivocation_proofs`. Gated by `checkpoint_enabled`. Tests:
  `logship_checkpoint.rs` + a `Checkpoint` unit test.
* **Scope:** a `Checkpoint { node, boot, window, lthash_root, pcr_quote_hash,
  … }` signed by the node key; emit on the advertise interval; verify the quote
  binding on receipt; make equivocation (§13) provably attributable to a quote.
* **Seam:** `logship` advertise path + `attest` quote; new signed type.
* **Test:** checkpoint sign/verify/tamper; a forged log root vs a signed
  checkpoint is caught. Deterministic.
* **Effort:** 1–1.5 wk. **Gating:** none. High conceptual value (it's the
  spine the original log-shipping design is built around).

### D2 — On-disk persistence
* **Goal:** survive restart — close §17. Today logs, replicas, fragments,
  shipped-window tracking, adopted manifests, and the reference audit are all
  in-memory.
* **Scope:** a storage trait + a default embedded store; persist the event log,
  LtHash windows, held fragments, adopted manifests, and audit chain; reload on
  start. Keep the in-memory impl for tests.
* **Seam:** new `store` abstraction behind `Node`'s maps.
* **Test:** kill/reload preserves roots, fragments, manifests, audit integrity.
* **Effort:** 1–2 wk. **Gating:** none.

### D3 — Erasure placement as the default — ✅ DONE
* **Goal:** make the bounded-fan-out erasure path (already built) the default
  durability mechanism, so durable evidence scales O(holders)/window not O(N)
  (`distributed-log-shipping-lthash.md` §18).
* **Delivered:** `NodeConfig::evidence_replication` now defaults `true` — the
  erasure-coded HRW holder vault is on out of the box. Low-risk because it only
  activates for nodes with *sealed log windows* (empty-log nodes no-op), so the
  whole suite passed unchanged. The digest-advertise *reconciliation* path
  (live replicas for divergence/equivocation) is **independent** of this and
  remains for that purpose; at scale it is tuned via `log_advertise_interval`
  while checkpoints (§9) + the erasure vault carry durability/tamper-evidence.
* **Note:** the full-replica path is not removed — it serves reconciliation, a
  different job than the durable vault. "Default replication" = the *durability*
  default is now bounded-fan-out erasure.

---

## Track E — distribution over the real transport

### E1 — Reference/promotion flows over HTTP
* **Goal:** the new gossip messages (`ReferenceManifest`, `ReferenceDigest`,
  promotion proposals/votes) currently exercised in the in-process harness run
  over the live `citadel-agent` HTTP transport.
* **Scope:** route the new `GossipMessage` variants through `citadel-agent`
  (the transport is message-agnostic, so mostly integration + tests); add HTTP
  smoke tests mirroring `logship_http.rs`.
* **Seam:** `citadel-agent` (Transport already carries `GossipEnvelope`).
* **Test:** real tokio agents converge on a gossiped manifest / promote a state.
* **Effort:** 1 wk. **Gating:** none. **Composes with** `mesh-integration-roadmap.md` item 1 (done).

### E2 — mTLS between agents via the TPM-held key
* **Goal:** authenticated agent-to-agent transport using the tpmd TPM-backed
  TLS key (already built for `tpmd`); deferred hardware item.
* **Scope:** wire `tpmd`'s `TpmSigningKey` into `citadel-agent`'s reqwest/axum
  as the client+server identity; peer-cert pinning to mesh keys.
* **Seam:** `tpmd::tls` + `citadel-agent::http`.
* **Test:** mutual-auth handshake; rejected unknown peer.
* **Effort:** 3–5 d. **Gating:** TPM-held key (hardware/vTPM).

---

## Recommended ordering

1. **A1** (corpus) — cheap, de-risks all later event-log work, no new deps.
2. **D1** (signed checkpoints) — high-value, software-only, unifies the two
   subsystems; can run in parallel with A1.
3. **A2 + A3** (X.509, structured extraction) — complete boot appraisal; A3
   depends on A1.
4. **B1 + B2** (real ingestion + RVP) — the bring-up onto real hardware/vTPM;
   B1 depends on A1.
5. **E1** then **E2** — put it all on the live transport.
6. **D2 + D3** (persistence, erasure default) — productionization, any time.
7. **C1** (IMA/runtime) — the largest, newest domain; schedule as its own
   project once boot appraisal is on hardware.

Rationale: do the cheap de-risking and the software-only high-value items
(A1, D1) first; finish boot appraisal (A2/A3) before crossing onto hardware
(B); leave the genuinely separate runtime domain (C1) for last.

## Cross-cutting follow-ups (small, fold into the above)
* Unused reason codes (`AGENT_VERSION_DEPRECATED`, `NETWORK_LOCATION_UNEXPECTED`,
  `CLOCK_SKEW_EXCESSIVE`, `ROLE_NOT_AUTHORIZED`) — wire or remove as their
  policies land.
* Quarantine scopes still declared-but-inert (`BlockWorkloadScheduling`,
  `CredentialRevoke`) — enforce when the corresponding subsystems exist.
* MMA agent self-measurement (PCR 14) emitted as an event-log entry so the same
  replay/appraise path covers the agent (`mma-upgrade.md` tie-in).
