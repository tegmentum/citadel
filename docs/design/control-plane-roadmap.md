# Citadel: Control-Plane & Dashboard Roadmap

Status: Plan
Project: Citadel
Audience: Architecture, Security, Platform, Operations, Frontend
Related: `monitoring-control-plane.md` (the design this scopes),
`distributed-attestation-mesh.md` (§5.3/§16/§17), `attestation-roadmap.md`
(the mesh stack this builds on, now essentially complete).

This scopes and orders the **observability + operator** layer above the mesh.
The mesh already decides trust and emits signed evidence of every decision; this
layer is a **verifying aggregator + operator console** — explicitly *not* a root
of trust (`monitoring-control-plane.md` §3, §8). It can ship incrementally:
everything through **CP4 is read-only** and cannot affect the mesh.

Each item: **goal · scope · seam · test · effort · gating**. Effort is rough
calendar (1 engineer). "Gating" = needs something outside the item itself.

| # | Item | Track | Effort | Gating |
|---|------|-------|--------|--------|
| M0 | Mesh: `Node` observer mode | Mesh prereq | ✅ done | no |
| M1 | Mesh: self-sign `AttestationResult` | Mesh prereq | ✅ done | no |
| CP1 | Observer ingestion → verify → fleet view | Read | ◑ store + aggregate done; observer-wiring + HTTP API remain | M0, M1 |
| CP2 | Agreement records + drill-down (§17.4) | Read | 1 wk | CP1 |
| CP3 | Evidence durability + reconstruction check | Read | 1–2 wk | CP1 |
| CP4 | Forensic timeline + audit-chain verify + change feed | Read | 1–2 wk | CP1, CP2 |
| CP5 | Operator workflow (signed policy / quarantine) | Write | 1–2 wk | CP1; RVP, quarantine |
| CP6 | Web dashboard SPA (all §16.3 views) | UI | 3–5 wk | CP1–CP5 view API |
| CP7 | Scale / HA (sharded observers, replica API) | Scale | 2–3 wk | CP1–CP5 |

The first useful product is **M0 + M1 + CP1 + CP2** — a verifiable fleet view
with the agreement-first node drill-down, read-only, ~3–4 weeks.

---

## Track M — mesh prerequisites (in `citadel-mesh`, small)

### M0 — `Node` observer mode
* **Goal:** let a node join, enrol, and receive all signed gossip **without**
  being a witness or enforcing anything — the control plane's ingestion member.
* **Scope:** a `NodeConfig` flag (e.g. `observer: bool`) that (a) excludes the
  node from witness assignment / skips `run_witness_duties`, (b) makes its own
  verdicts non-counting (it still *verifies* for the dashboard, just doesn't
  gossip binding `AttestResult`s), (c) takes no quarantine-enforcement role. It
  still gossips membership, runs anti-entropy, and replicates evidence (so it can
  prove durability) if desired.
* **Seam:** `node.rs` (`run_witness_duties`, `witnesses_for`/`witness::assign`
  callers), `NodeConfig`.
* **Test:** an observer in a mesh receives every peer's `AttestResult` /
  `AppResult` / `ReferenceManifest` but is never assigned as a witness and casts
  no counting verdict; the mesh's quorum math is unchanged with it present.
* **Effort:** 2–3 d. **Gating:** none.

### M1 — self-sign `AttestationResult`
* **Goal:** make a verifier's verdict verifiable **detached** from its gossip
  envelope, so the CP can store, relay, and audit it (today its authenticity
  rests only on the signed `GossipEnvelope`).
* **Scope:** add a verifier signature + `verify_signature()` to
  `AttestationResult`, mirroring `AppAttestationResult` (`signing_bytes` over
  subject/verifier/result/reason_codes/policy_revision/confidence/tick;
  `kp.sign`; verify against the verifier's mesh key). Sign at emission in
  `on_evidence`; verify on receipt.
* **Seam:** `types.rs::AttestationResult`, `node.rs` (emission/receipt),
  `application.rs` as the pattern.
* **Test:** a tampered verdict fails `verify_signature`; a relayed (re-enveloped)
  verdict still verifies; round-trip through serde.
* **Effort:** 1–2 d. **Gating:** none. *(The one substantive in-mesh change the
  whole layer needs.)*

---

## Track CP — the control plane (`citadel-control-plane`, new crate)

A new crate: an **observer `Node`** + ingestion/verify/aggregate/store + an axum
API. Reuses `citadel-mesh`, `citadel-agent` transport, `tpm-tls` (mTLS), and the
existing signed artifacts.

### CP1 — observer ingestion → verify → fleet view  (read-only)
* **Goal:** stand up the CP process: an observer node feeding a verified
  current-state store, with the fleet/node read API.
* **Scope:** run an observer `Node` (M0) inside the CP; a verify+aggregate
  pipeline that checks every signed artifact and maintains per-node current
  state (liveness, trust, last verdict, policy revision); endpoints
  `GET /v1/nodes`, `GET /v1/nodes/{id}`, `GET /v1/mesh/health` (trust histogram +
  mesh-health %). Poll agent `GET /v1/mesh/status` as a snapshot supplement.
* **Seam:** new crate; `citadel-mesh::Node` (observer), `membership`,
  `GossipMessage::{AttestResult,AppResult,ReferenceManifest}`,
  `citadel-agent::http` transport.
* **Test:** a multi-node harness mesh + an in-process CP observer; assert the
  CP's `/v1/mesh/health` trust histogram matches the mesh's actual trust states,
  and a node going Suspicious shows up after gossip converges.
* **Effort:** 1–2 wk. **Gating:** M0, M1.
* **Done so far:** the `citadel-control-plane` crate with a **pluggable
  `ControlPlaneStore`** (trait + `MemStore`; backend is a deployment choice) and
  `ControlPlane<S>` — `ingest_member` / `ingest_verdict` (**re-verifies the M1
  signature**, rejecting forged/unknown-verifier verdicts before they reach the
  store), CP-**derived** trust, `node_view` / `nodes` / `fleet_health` (§17.1
  rollup, observers excluded). Tested (store roundtrip, forged-verdict rejection,
  fleet rollup). **Remaining for CP1:** wire an observer `Node` (M0) as the live
  feed + the axum read API (`/v1/nodes`, `/v1/mesh/health`).

### CP2 — agreement records + drill-down  (read-only, the headline)
* **Goal:** the central object (`monitoring-control-plane.md` §6.1 / §17.4):
  per-`(subject, policy_revision)`, the set of **verified signed verdicts**, the
  **recomputed assigned-witness set**, agree/total, missing reporters, dissenters
  + reasons, expected-vs-observed.
* **Scope:** an `AgreementRecord` aggregator keyed by subject+revision; recompute
  the witness set with the same `witness::assign` (HRW) the mesh uses; endpoints
  `GET /v1/nodes/{id}/agreement`, `GET /v1/agreement/{subject}/{rev}` (each signed
  report). Distinguish **silence** (assigned witness with no report) from
  agreement.
* **Seam:** `witness::assign`, the M1-signed verdicts, `ReasonCode` (carries the
  PCR/profile delta).
* **Test:** inject N witnesses with mixed verdicts → the record shows the exact
  tally, names the missing assigned witnesses, and lists dissenters; matches the
  §17.4 example shape.
* **Effort:** 1 wk. **Gating:** CP1.

### CP3 — evidence durability + reconstruction check  (read-only)
* **Goal:** *prove* (not assert) that a record's evidence is reconstructable
  (§17.3).
* **Scope:** track per-record fragment advertisements + receipts; the CP gathers
  ≥ threshold fragments and **reconstructs** (or verifies receipts + the erasure
  math); checkpoint **chain continuity** from the signed `LogCheckpoint`s.
  Endpoint `GET /v1/nodes/{id}/evidence` (`EvidenceDurabilityView`).
* **Seam:** `erasure.rs`, `logship::{LogFragment,DigestAdvertisement,Checkpoint}`,
  `evidence::EvidenceReceipt`.
* **Test:** with k-of-n fragments present the view says PASS + reconstructs;
  drop below threshold → it reports the shortfall, not a false PASS.
* **Effort:** 1–2 wk. **Gating:** CP1.

### CP4 — forensic timeline + audit verification + change feed  (read-only)
* **Goal:** "what changed", per subject, every entry linked to the signed
  artifact behind it; a live feed.
* **Scope:** an append-only per-subject timeline (enrol → trust transitions with
  the triggering agreement record → quarantine proposal/vote/enact → operator
  action → recovery); verify the agents' `reference_audit`/`app_audit`
  hash-chains; a change feed (SSE/websocket) reproducible from signed artifacts.
  Endpoints `GET /v1/nodes/{id}/timeline`, `GET /v1/events?since=…`.
* **Seam:** `EvidenceChain` (audit), the time-series store, `quarantine.rs`.
* **Test:** a scripted scenario (boot → tamper → quorum-distrust → quarantine →
  rejoin) yields a timeline whose entries each resolve to a verifiable artifact;
  a broken audit chain is flagged.
* **Effort:** 1–2 wk. **Gating:** CP1, CP2.

### CP5 — operator workflow  (the first **write** path)
* **Goal:** signed, audited operator actions that enter the mesh as **inputs**,
  not commands (§8).
* **Scope:** `POST /v1/policies` (publish a signed `ReferenceManifest` via the
  RVP path → gossip), `POST /v1/quarantine/operator-action` (the operator
  sign-off severe scopes require), enrollment front-door proxy. Every write needs
  an operator/authority signature; the CP relays it and records it in its own
  audit log. Optionally co-sign/quorum-gate severe scopes.
* **Seam:** `rvp.rs` (`issue_*`), the manifest gossip path, `quarantine.rs`
  (operator-approved enactment), a CP audit log.
* **Test:** a published policy is adopted by mesh nodes (matching build passes,
  others `REFERENCE_UNKNOWN`); a forged operator action fails signature at the
  nodes; the CP audit log is hash-chained.
* **Effort:** 1–2 wk. **Gating:** CP1; reuses RVP + quarantine.

### CP6 — web dashboard SPA
* **Goal:** the §16.3 views, **agreement-first**, for operators.
* **Scope:** a single-page app over the CP view API: Fleet / Node / Agreement /
  Evidence / Quarantine / Forensic-timeline / Policy-compliance; live updates via
  the change feed; operator actions gated by RBAC. Agreement-first framing (never
  a bare alert — show who agrees + expected-vs-observed).
* **Seam:** the CP3–CP5 view API; auth (OIDC or mTLS).
* **Test:** view contract tests against recorded CP payloads; an e2e that drives
  a scenario and asserts the rendered agreement/evidence blocks.
* **Effort:** 3–5 wk. **Gating:** the CP1–CP5 view API. **Decision:** frontend
  stack + auth (open question in the design).

### CP7 — scale / HA
* **Goal:** 10k+ nodes; resilient CP.
* **Scope:** shard observer nodes by HRW subject-space; horizontally scale the
  read API over a shared store; roll up steady-state "all-agree" verdicts while
  keeping full fidelity for disagreement/transitions; retention policy.
* **Seam:** CP1–CP5; the store choice (open question).
* **Test:** a synthetic 10k-node verdict stream sustains ingestion within budget;
  losing an observer shard self-heals via anti-entropy.
* **Effort:** 2–3 wk. **Gating:** CP1–CP5.

---

## Recommended ordering
1. **M0 + M1** — small in-mesh prereqs; unblock everything, mergeable on their
   own (observer mode is independently useful; the signature strengthens audit).
2. **CP1 + CP2** — the minimum verifiable product: fleet view + agreement
   drill-down. Read-only; ~3–4 wk total with M0/M1.
3. **CP3 + CP4** — durability proof + forensics; completes the read-only console.
4. **CP5** — the operator workflow (first write path), once the read views give
   operators the context to act.
5. **CP6** — the SPA (can start its view-contract work against CP1–CP4 payloads
   early; full build after CP5).
6. **CP7** — scale, when fleet size demands it.

## Open decisions (carried from the design)
1. Store: embedded (`secure-log` / SQLite) vs. external TSDB — depends on
   retention/scale targets (affects CP4/CP7).
2. Operator-action gating: single operator signature vs. quorum/co-sign for
   severe scopes (CP5).
3. Frontend stack + auth (CP6).
4. A read-only **TUI** (reuse `tpm-tui` patterns) before/besides the SPA for
   air-gapped ops — could slot in after CP2 cheaply.

## What this reuses (already built)
Signed verdicts / app results / manifests / checkpoints / receipts; membership +
liveness; `witness::assign`; erasure + reconstruction; the audit chains; the RVP
(`rvp.rs`); mTLS (`tpm-tls`) + the agent transport; the agent `/v1/mesh/status`.
**New code:** M0/M1 (small, in-mesh) + the `citadel-control-plane` crate + the SPA.
