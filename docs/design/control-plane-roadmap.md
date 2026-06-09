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
| CP1 | Observer ingestion → verify → fleet view | Read | ✅ done | M0, M1 |
| CP2 | Agreement records + drill-down (§17.4) | Read | ✅ done | CP1 |
| CP3 | Evidence durability + reconstruction check | Read | ✅ done | CP1 |
| CP4 | Forensic timeline + audit-chain verify + change feed | Read | ✅ done | CP1, CP2 |
| M2 | Mesh: gossip-wire quarantine (proposal/vote/operator-approval) | Mesh prereq | ✅ done | no |
| CP5 | Operator workflow (signed policy + quarantine) | Write | ✅ done | CP1; RVP, quarantine, M2 |
| CP6 | Web dashboard SPA (agreement-first) | UI | ✅ done (dependency-free SPA) | CP1–CP5 view API |
| CP7 | Scale / HA (sharded observers, rollup, retention) | Scale | ✅ done (sharding + rollup + retention; load-rig benchmark remains) | CP1–CP5 |

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

### M2 — gossip-wire quarantine
* **Goal:** make quarantine a mesh-propagated decision (it was a harness-only API
  + a pure `decide_quarantine` tally) so proposals, votes, and operator approvals
  flow over gossip and every node converges on the same enactment — and the CP
  can relay an operator sign-off (unblocks CP5's quarantine action).
* **Done:** `GossipMessage::{QuarantineProposal,QuarantineVote,QuarantineApproval}`
  + `OperatorQuarantineApproval` (operator-signed, accepted only from a node's
  trusted `operator_keys`). `Node`: `propose_and_broadcast_quarantine` (broadcast
  + self-vote if an assigned witness), receipt handlers that record + tally,
  `tally_and_maybe_enact` (every node tallies the same eligible-witness set via
  `witness::assign` and enacts in its own view), `relay_quarantine_approval` +
  `authorize_operator_key`. `broadcast()` already reaches all members, so each
  artifact is broadcast once (no flooding).
* **Test:** a light scope enacts mesh-wide from witness votes; full isolation
  waits for a relayed operator approval, then enacts everywhere; an untrusted
  operator's approval is ignored.

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
* **Done:** the `citadel-control-plane` crate — a **pluggable `ControlPlaneStore`**
  (trait + `MemStore`) and `ControlPlane<S>`: `ingest_member` / `ingest_verdict`
  (**re-verifies the M1 signature**, rejecting forged/unknown-verifier verdicts
  before the store), CP-**derived** trust, `node_view` / `nodes` / `fleet_health`
  (§17.1 rollup, observers excluded). Live feed: `Node::drain_observed_verdicts`
  (observer buffers verified verdicts) + `ControlPlane::observe(node)` pulls
  members + verdicts. Read API (`api::router`): `GET /v1/mesh/health`,
  `/v1/nodes`, `/v1/nodes/{id}`. Tested: store roundtrip + forged-verdict
  rejection + fleet rollup (unit); observe-a-harness-mesh, a tampered node
  surfacing as `suspicious`, and the HTTP read API (integration).

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
* **Done:** `ControlPlane::agreement(subject) -> AgreementView` — **recomputes**
  the assigned witness set with the mesh's own `witness::assign` (HRW; mesh
  params captured by `observe`), then over the latest policy revision reports
  `agree` / `reported` / `quorum_threshold`, the **silent** assigned witnesses
  (no report ≠ agreement), and **dissenters** with their reason codes
  (expected-vs-observed). `GET /v1/nodes/{id}/agreement`. Tested over a real
  mesh: the CP's recomputed assignment **equals** the mesh's; a tampered node
  yields dissenters with reasons and `agree < assigned`; a healthy node has a
  quorum agreeing and no dissent.

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
* **Done:** owner-centric durability — `Node::evidence_durability()` exposes per sealed window the erasure `threshold`/`total` + how many holders returned a **signature-verified** receipt (`acked`, verified in `on_fragment_ack`); `ControlPlane::poll_durability(node)` pulls it (receipts flow owner↔holder, so this is a per-node poll, not the observer feed), `evidence_view` marks each record `reconstructable` iff `holders_acked >= threshold`, and `fleet_health` rolls up `evidence_durability_pct` (§17.1). `GET /v1/nodes/{id}/evidence`. Tested: a real seal+ship mesh proves a 3-of-5 record reconstructable from holder receipts; a sub-threshold record is **not** durable (no false PASS).

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
* **Done (policy write path, end to end):** `OperatorAction` (a *registered*
  operator's signature over `(kind, target)`); `submit_policy` validates four
  things — the action authorizes *this* manifest, the operator is registered, its
  signature verifies, and the manifest's **own authority signature** verifies —
  then appends a BLAKE3 hash-chained `OperatorAuditEntry` and **enqueues** the
  manifest; `drain_pending_manifests` lets the host loop relay it through the
  observer node (decoupling the API from the node). `publish_policy` is the
  in-process convenience. `POST /v1/policies` (validate+audit+enqueue; `WriteError`
  → 403/400), `GET /v1/audit`. Nodes still adopt only if they trust the authority
  — the CP holds no trust-deciding key. Tested: an authorized publish (lib + live
  HTTP) is adopted by the mesh and audited; unauthorized/target-mismatch/forged
  writes are refused, not relayed, not audited; the audit chain links + verifies.
  Gating default is **single authorized-operator signature**; quorum/co-sign for
  severe scopes is a documented extension (carry multiple `OperatorAction`s + a
  per-kind threshold).
* **Done — quarantine operator-action (after gossip-wiring the mesh):** the
  mesh's quarantine flow is now gossip-wired (Track-M below) —
  `GossipMessage::{QuarantineProposal,QuarantineVote,QuarantineApproval}` +
  `OperatorQuarantineApproval`. The CP closes the loop: `submit_quarantine_approval`
  (operator registered + signature verifies → audit → enqueue) +
  `relay_quarantine_approval` (drains + relays through the observer node's
  `relay_quarantine_approval`). Tested end-to-end: a witness proposes full
  isolation, witnesses approve but it's gated; the CP relays the operator's
  signed approval and **the mesh enacts full isolation fleet-wide**; the relay is
  audited; an unregistered operator's approval is refused.
* **Done — trust-freeze fix:** the verifier's *direct* `set_trust` in
  `on_evidence` is now gated on quarantine, so an isolating quarantine's trust
  stays `Isolated` instead of being downgraded to `Suspicious` by the next
  challenge (matching the freeze `aggregate_trust` already applies). Asserted in
  the quarantine-gossip test.

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
* **Done (v1, dependency-free):** an embedded single-page console
  (`assets/dashboard.html`, served at `GET /` via `api::router`; `api::serve`
  binds it) — **no JS/WASM build step**, so CI stays cargo-only. It polls the
  JSON endpoints (3s) and renders **agreement-first**: fleet health histogram +
  mesh-health/durability %, a node table (color-coded trust), and a node
  drill-down that leads with "*N of M assigned witnesses agree*" + dissenters
  with reasons + silent witnesses (never a bare alert), then evidence durability
  and the per-node timeline; plus the live change feed (`/v1/events?since=`) and
  the operator audit (`/v1/audit`). Tested: `GET /` serves the SPA wired to the
  CP endpoints. **Follow-up:** auth (OIDC/mTLS) and a framework build if richer
  UI is wanted — the JSON API is stable, so that's additive.

### CP7 — scale / HA
* **Goal:** 10k+ nodes; resilient CP.
* **Scope:** shard observer nodes by HRW subject-space; horizontally scale the
  read API over a shared store; roll up steady-state "all-agree" verdicts while
  keeping full fidelity for disagreement/transitions; retention policy.
* **Seam:** CP1–CP5; the store choice (open question).
* **Test:** a synthetic 10k-node verdict stream sustains ingestion within budget;
  losing an observer shard self-heals via anti-entropy.
* **Effort:** 2–3 wk. **Gating:** CP1–CP5.
* **Done (scale-out):** **HRW observer sharding** (`shard.rs`) — a subject's
  history is owned by the top-`replication` shards by the same rendezvous hashing
  the mesh uses for witnesses; `ControlPlane::set_shard`/`set_shards` +
  `responsible_for` gate verdict/event/durability ingestion (membership stays
  replicated to every shard for keys + roster). Tested: ownership is balanced and
  removing a shard reassigns only its subjects; two shards partition a live
  mesh's subject space with no overlap and full coverage; a surviving shard takes
  over a lost shard's subjects. **Steady-state rollup** (`rollup_verdicts`)
  compacts each subject's verdict history keeping full fidelity for transitions
  (first/last/changes per verifier) — derived trust + agreement unchanged.
  **Retention** (`retain_events`) prunes old timeline events; the audit chain is
  never pruned. **Load smoke:** 600 subjects × 4 verifiers ingest + aggregate
  correctly. Store ops `replace_verdicts`/`prune_events` added to all three
  backends. **Deployment:** the `control-plane` server binary
  (`src/bin/control-plane.rs`) serves the dashboard + API over an env-selected
  store (`mem`/`redb`/`pg`) and an optional shard identity — run N stateless
  replicas over a shared `PgStore` for the scaled read API; runtime-smoke-checked
  (`GET /` + endpoints serve). Topology, env, and the ingestion loop are in
  `docs/deploy/control-plane.md`. **Load rig:** a runnable 10k-node ingestion
  benchmark (`tests/cp7_load_bench.rs`, `#[ignore]`d) + methodology/targets in
  `docs/deploy/load-rig.md` — written and compile-checked, **not yet run**. The
  one networked piece left to assemble (from the existing agent + CP crates) is
  the combined observer-ingestion daemon; everything it calls (`observe`,
  `poll_durability`, the drain/relay loop) exists and is tested.
* **Done (durable store backends):** the `ControlPlaneStore` trait now has two
  durable impls beside `MemStore`. **`RedbStore`** — embedded, pure-Rust ACID KV
  ([redb]); default-built + tested (round-trips the verified facts, survives a
  reopen, drives a `ControlPlane` like `MemStore`); the first durable step and
  the per-shard local store. **`PgStore`** (feature `postgres-store`) — Postgres
  via the blocking client behind a `Mutex`: current-state rows (`nodes`,
  `durability`) + append tables (`verdicts`, `events`) indexed by `subject`/`tick`
  + the ordered `operator_audit` chain; the shared store for the scaled read API,
  with TimescaleDB continuous-aggregates the natural home for the steady-state
  rollup + retention. Compile-checked in CI; its round-trip test is `#[ignore]`d
  (needs `CITADEL_PG_TEST_URL`). **Remaining for CP7:** observer sharding by HRW
  subject-space, replica read API, the rollup/retention jobs, the 10k-node load
  test.

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
