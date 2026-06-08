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
| A1 | Real-platform event-log corpus validation | Boot appraisal | ✅ done | corpus captured (OVMF) |
| A2 | X.509 / CA-chain authority validation | Boot appraisal | ✅ done (x509-path crate) | no |
| A3 | Structured `ArtifactIdentity` extraction from events | Boot appraisal | ✅ done | no |
| B1 | Real event-log ingestion (vTPM `read_event_log`) | Hardware bring-up | ✅ done (vTPM) | done on vTPM; /sys+HW remain |
| B2 | Signed reference values from a real RVP | Hardware bring-up | 1 wk | build pipeline |
| C1 | IMA / runtime measurement (event-log Phase D) | Runtime | ◑ software done | real IMA corpus |
| D1 | Signed quote-bound checkpoints (log-ship §9–10) | Durability | ✅ done | no |
| D2 | On-disk persistence (log-ship §17) | Durability | ✅ done | no |
| D3 | Erasure placement as the default replication | Durability | ✅ done | no |
| E1 | Reference manifest flows over HTTP transport | Distribution | ✅ done | no |
| E2 | mTLS between agents via the TPM-held key | Distribution | ✅ done | verified on vTPM |

---

## Track A — finish boot-appraisal (no new domain, mostly no hardware)

### A1 — Real-platform event-log corpus validation — ✅ DONE
* **Goal:** prove `parse_tcg` / `replay` against logs real firmware emits, not
  just hand-built ones. The robustness risk flagged in `event-log-attestation.md`.
* **Delivered:**
  - A real **OVMF firmware corpus entry** captured on Linux
    (`tests/fixtures/eventlog/ubuntu-24.04-ovmf-amd64.{bin,sha256}`): the
    parser + replay reproduce **11 firmware PCRs** exactly against the live
    quote. (Quote-only PCRs the boot log can't explain — 10 = IMA runtime,
    11–13/15 never-extended zeros — are correctly skipped.)
  - A **fixture-driven corpus test** (`tpm-core/tests/eventlog_corpus.rs`):
    scans `<name>.bin` + `<name>.sha256`, requires PCR 0 (CRTM) so an empty log
    can't pass vacuously, and asserts every PCR the firmware log measures equals
    the quote. New fixtures validate automatically.
  - **Parser hardening** for real-log warts, with regression tests:
    crypto-agile **multi-bank** records (sha1+sha256 — replay picks the right
    bank), and trailing **padding / `0xFFFFFFFF` terminator** ignored.
  - A **turnkey capture lab**: `scripts/capture-eventlog.sh` (x86, KVM/HVF) +
    `scripts/capture-eventlog-aarch64.sh` (arm64 HVF) + the guest cloud-init,
    plus `docs/a1-capture-handoff.md`. **`SwtpmManager`** revived
    (`tpm_core::backend::swtpm`) to manage the real `swtpm` daemon.
* **More breadth (optional):** add fixtures from other firmwares (bare-metal
  vendor BIOS, different OVMF versions) the same way — each just drops two files
  in and the harness validates them.
* **Unblocks:** **A3** (structured `ArtifactIdentity` from real events) and the
  **B1-firmware tail** now have a real corpus to work against.
* **Add more:** any real `/sys/.../binary_bios_measurements` + its
  `/sys/class/tpm/tpm0/pcr-sha256/*` dropped into `tests/fixtures/eventlog/` (as
  `<name>.bin` + `<name>.sha256`) validates immediately — see
  `docs/a1-capture-handoff.md` for the capture paths (no QEMU needed for a real
  box; the lab for reproducible firmware variants).
* **Seam:** `tpm_core::eventlog::parse_tcg`; `tests/fixtures/eventlog/`.

### A2 — X.509 / CA-chain authority validation — ✅ DONE
* **Goal:** an authority that is a **CA** authorizes many leaf images without
  pinning each — beyond the opaque-blob membership of the original Secure Boot
  work.
* **Delivered as shared infra:** a new repo **`~/git/pkcs11-x509`** with a
  native `x509-path` crate (chain-to-anchor: parse + signature verify + validity
  + CA constraints + `dbx` revocation; pluggable `CertVerifier` seam, native by
  default, routable to the PKCS#11 `verify()` primitive) plus a WIT
  `tegmentum:x509-path` contract and a WASM-component wrapper. Reusable by any
  project needing chain-to-anchor.
* **Wired into Citadel** behind the `x509-authority` feature (core stays lean by
  default): `FleetArtifactPolicy::trust_ca` / `as_of` + `chains_to_ca`, folded
  into `authority_permits` — an `EV_EFI_VARIABLE_AUTHORITY` is accepted if it is
  a pinned `db` entry **or** chains to a trusted `db` CA, and `dbx` still blocks.
* **Tests:** `x509-path` 8 unit tests (rcgen chains); Citadel
  `tests/x509_authority.rs` (CA-chain accepted; untrusted-CA denied; dbx-revoked
  denied) under the feature.
* **Remaining:** parsing the real `EV_EFI_VARIABLE_AUTHORITY` `EFI_SIGNATURE_DATA`
  wrapper (vs. a raw cert) and a real time source for `as_of` — both intersect A1
  (real corpus). X.509 name-constraints / EKU are documented non-goals of
  `x509-path` for now.

### A3 — Structured `ArtifactIdentity` extraction from events — ✅ DONE
* **Goal:** derive `(component, version)` **directly from the event log**
  instead of only from a signed digest→identity manifest — so policy can judge a
  never-before-seen build's version without a manifest naming it.
* **Delivered (against the real A1 corpus):**
  - `MeasurementEvent::measured_text` — recovers the **digest-bound** payload of
    an event, reconciling real GRUB logging (it prefixes a descriptive
    `"<label>: "` and hashes only the payload, sometimes with a trailing NUL, so
    the old exact-bytes `data_is_measured` never held on real logs).
  - `extract_kernel_artifact` / `extract_kernel_cmdline` (`reference.rs`) — pull
    the **booted** kernel `vmlinuz-<ver>` + command line out of the digest-bound
    `EV_IPL` events and parse the version (`6.8.0-117` → `[6,8,0,117]`).
  - `appraise_eventlog` now gates the **booted** cmdline (require/deny) and the
    event-derived kernel **version baseline / denylist** with no manifest —
    `FleetArtifactPolicy::version_denied` (channel-independent, since the channel
    isn't knowable from the log).
* **Real-log correctness:** policy applies to the *booted* command line only,
  not the full `menuentry`/`submenu` config GRUB also measures (which enumerates
  every entry incl. recovery `nomodeset`) — so a `deny_cmdline("nomodeset")`
  does **not** falsely trip on the recovery entry.
* **Tests:** `tpm-core` `measured_text` unit (label + NUL recovery);
  `citadel-mesh/tests/a3_artifact_extraction.rs` over the real OVMF corpus —
  extracts `6.8.0-117`, gates by baseline/denylist with no manifest, and proves
  the recovery-menuentry non-false-positive.
* **Not derivable from the log (still need a manifest/authority):** `channel`
  and `publisher`. PE-COFF version-resource extraction from
  `EV_EFI_BOOT_SERVICES_APPLICATION` device paths is a possible follow-up; the
  GRUB/IPL cmdline path covers the kernel today.

---

## Track B — run on real hardware (the "runs on a real machine" bridge)

### B1 — Real event-log ingestion — ✅ DONE (vTPM)
* **Goal:** `read_event_log` returns a real, live-quote-consistent log, not the
  `MockBackend` synthetic one.
* **Delivered:** `VtpmBackend` (`crates/vtpm-backend`) tracks every PCR extend
  and overrides `read_event_log` / `measure_event` to synthesize a measured-boot
  log that replays to the **live vTPM PCR values**. A software vTPM has no
  firmware event log (that's a UEFI artifact), so the log is reconstructed from
  what we measured — `replay(log) == quote` over a genuine TPM2 quote. Verified
  by `synthesized_event_log_replays_to_the_live_vtpm` against the real component
  (full 10-test vTPM suite passes in ~155s).
* **Remaining:** ingesting a *firmware* `/sys/.../binary_bios_measurements` /
  UEFI TCG2 log on bare metal (then `parse_tcg` consumes it directly — the
  parser already exists), and wiring the `MeasurementEvent` stream into the
  LtHash log (`logship::append_event`) to fill §6. Needs bare-metal UEFI, not a
  vTPM.

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

### C1 — IMA / runtime (event-log Phase D) — ◑ parser + policy built; real corpus + shipping pending
* **Goal:** attest measurements that happen *after* boot — file/exec integrity
  via Linux IMA (PCR 10), ongoing rather than one-shot.
* **Built:**
  - `tpm_core::ima` — parser for the **ASCII** IMA list
    (`ascii_runtime_measurements`), handling `ima-ng` / `ima-sig` / legacy `ima`
    templates → `(pcr, template_hash, file algo+hash, path, sig)`. Skips
    unrecognized lines (count returned) rather than failing the whole log. (The
    ASCII form is parsed deliberately — the binary `d-ng` field layout is the
    kind of thing that bites you without real data; ASCII is unambiguous.)
  - `citadel_mesh::runtime::RuntimePolicy` — content-hash runtime appraisal:
    a **denylist** (known-bad file hashes, the `dbx` analogue) and an optional
    **allowlist** (lockdown: only listed hashes may run); empty = report-only.
    `appraise` returns the violating files (report-always, like app appraisal).
  - Fixture-driven corpus harness (`tpm-core/tests/ima_corpus.rs`) + capture
    wired into the lab (`<name>.ima.ascii`) — see `docs/a1-capture-handoff.md`.
  - **Wired into node trust** (`Node::report_runtime` + `runtime_escalated`): a
    **denied** (known-bad) file that executed escalates the node to distrust,
    mirroring the P3 app-escalation path — sticky (a clean boot quote can't clear
    it via `aggregate_trust`) and persisted across restart (`NodeSnapshot`). An
    allowlist miss is report-only (lockdown enforcement is a control-plane
    choice). Tested in `tests/runtime_escalation.rs`.
  - **Shipped through the LtHash pipeline** (`Node::ingest_own_ima`): a node
    ingests its own IMA list, preserving each measured file as an LtHash log
    element — so runtime evidence is reconciled, gossiped, and held across the
    mesh exactly like boot evidence (and rides the `NodeSnapshot` for free) —
    while appraising it against the runtime policy.
  - **Append-only PCR class** (`PcrClass::Runtime`): PCR 10 grows monotonically
    as files are measured, so it is skipped in value-tier matching and appraised
    via the IMA log instead — a changing PCR-10 value no longer mints distrust
    (contrast-tested against `Strict` to prove PCR 10 *is* appraised).
  - Tests: `tests/ima_shipping.rs` (LtHash preservation; policy appraisal on
    ingest; Runtime-class skip vs. Strict-distrust contrast).
  - **Shipped over the attestation path** (`AttestationEvidence.ima_log` +
    `Node::stage_ima`): an attester ships its IMA list in the evidence it
    produces; the verifying witness appraises it and, on a known-bad file,
    **fails the reported verdict** (`REFERENCE_DENIED`) so the witness *quorum*
    carries the runtime failure to every node — not just the witnesses that saw
    the evidence — plus the local sticky `runtime_escalated`. Tested in
    `runtime_escalation.rs` (`a_shipped_ima_log_distrusts_over_the_attestation_path`).
* **Remaining (real-data only):** validate the parser against a **real** IMA
  list — needs a kernel booted with an IMA policy (e.g. `ima_policy=tcb`; a
  default cloud image emits only `boot_aggregate`), captured via the lab
  (`docs/a1-capture-handoff.md`); plus an agent-side reader of
  `/sys/.../ascii_runtime_measurements` to feed `stage_ima`. Optional: a
  periodic PCR-10 re-quote cadence.
* **Seam:** `tpm_core::ima`; `citadel_mesh::runtime`; `node::report_runtime` /
  `ingest_own_ima` / `stage_ima`; `reference::PcrClass::Runtime`; `logship`;
  `AttestationEvidence.ima_log`.

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

### D2 — On-disk persistence — ✅ DONE
* **Goal:** survive restart — close §17. Today logs, replicas, fragments,
  shipped-window tracking, adopted manifests, and the reference audit are all
  in-memory.
* **Delivered:** `store::{Store, MemStore, FileStore}` (atomic write, path-
  traversal-safe) + `Node::snapshot`/`restore` and `persist`/`hydrate`; a
  `NodeSnapshot` captures the durable evidence (own log, replicas, fragments,
  manifests, both audit chains, app results/scopes, sealed roots, checkpoints).
  Membership/trust deliberately excluded — re-earned via gossip. Tests:
  `persistence.rs`.
* **Gating:** none.

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

### E2 — mTLS between agents via the TPM-held key — ◑ crypto core done (verified on vTPM); transport wiring remains
* **Goal:** authenticated agent-to-agent transport where each side's TLS key is
  TPM-resident.
* **Delivered — new reusable `tpm-tls` crate** (backend-agnostic over
  `TpmBackend`; works with vTPM/swtpm/hardware):
  - `TpmTlsIdentity::new` — the TPM **mints its own self-signed cert** via
    `rcgen`'s remote-signing seam (the TPM signs the cert), including a
    `TPM2B_PUBLIC` ECC-point parser for `rcgen`'s `public_key()`.
  - the TPM **signs every handshake** (rustls `SigningKey`/`Signer` →
    `TPMT_SIGNATURE` → DER ECDSA), private key never leaving the TPM.
  - **mutual-TLS** `server_config` / `client_config` with **certificate
    pinning** (mesh identity = the exact peer cert; no CA) — handshake signature
    still verified so pinning proves key possession.
  - **Verified on the real vTPM** (`tests/mtls_handshake.rs`, ~62 s): two
    TPM-held identities complete mutual TLS; an unpinned client is rejected; an
    impostor server cert is rejected. (Needs a *persisted* vTPM — the ephemeral
    one returns a non-signature fallback.)
* **Transport wired (`citadel-agent::http`):** `mtls_client` builds a reqwest
  client with the TPM mTLS identity (pinning the peer roster); `serve_mtls`
  serves the axum router over mutual TLS via `axum-server`;
  `HttpTransport::with_client` injects the mTLS client. **Proven end-to-end on
  the real vTPM** (`tests/mtls_transport.rs`, ~34 s): a pinned peer's gossip
  POST flows over real TCP+mTLS and is accepted; an unpinned client is refused.
* **Cert distribution (done):** a node advertises its TLS cert
  (`Node::set_tls_cert`); peers assemble the pinnable roster (`Node::tls_roster`)
  two ways — (1) **signed enrolment claim** (`EnrollmentClaim.tls_cert`, bound to
  the signature) so a joining node's cert arrives on the bootstrap/plain channel
  *before* mTLS is up (avoids the chicken-and-egg of distributing certs over the
  very channel they'd protect), and (2) **membership gossip** (`MemberUpdate.
  tls_cert`) for steady-state roster updates among admitted peers. Tested:
  `tests/tls_roster.rs` (gossip propagation; admission-time pinning) + the
  enrolment-claim signature path.
* **Agent binary wired (generic backend):** `Attestor` now holds an `Arc<dyn
  TpmBackend>` (exposing `backend_arc`) so the *same* TPM that quotes also mints
  the TLS key; `build_node_with_backend` lets the binary pick the backend
  (`main.rs::make_backend`, default `MockBackend` for the demo);
  `mint_tls_identity` creates the ECC key, self-signs the cert in the TPM, and
  `set_tls_cert`s it; `main.rs` runs **mutual TLS** (`serve_mtls` + `mtls_client`
  off the pinned roster) when a real backend mints an identity and peer certs are
  available, else plain HTTP — so the all-mock demo is unchanged while a real
  deployment gets mTLS by swapping the backend. Graceful fallback tested
  (`tests/tls_identity.rs`: MockBackend → `None` → plain HTTP).
* **Optional follow-up:** a real hardware-TPM backend behind `make_backend`;
  refactor `tpmd::tls` onto `tpm-tls` to dedupe the signing-key code.
* **Seam:** `tpm-tls`; `citadel-agent::http` + `main.rs` (done); mesh enrolment +
  membership cert distribution (done); `Attestor::backend_arc` (done).

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
  policies land. (`AGENT_VERSION_DEPRECATED` / `ROLE_NOT_AUTHORIZED` are realized
  by **application appraisal**, below.)
* Quarantine scopes still declared-but-inert (`BlockWorkloadScheduling`,
  `CredentialRevoke`) — **enforced by application appraisal** (`application-appraisal.md`
  P2), which gives these scopes their app-scoped teeth.
* MMA agent self-measurement (PCR 14) emitted as an event-log entry so the same
  replay/appraise path covers the agent (`mma-upgrade.md` tie-in).

## Related: application-level appraisal (separate design)
`application-appraisal.md` addresses the asymmetry that a TPM/boot anomaly drives
quarantine but a failing **registered application** has no detect/respond path.
It adds app-scoped appraisal (reusing `FleetArtifactPolicy` + `ReferenceManifest`),
a **report-always** signed `AppAttestationResult` recorded in the evidence chain,
a **graded** response that finally enforces the two inert quarantine scopes, and
escalation to node trust only on policy threshold — keeping node-quarantine for
platform compromise. P1+P2 are software-only; P4 (real app measurement) depends
on C1 (IMA).
