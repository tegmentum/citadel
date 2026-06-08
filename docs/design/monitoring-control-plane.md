# Citadel: Monitoring, Control Plane & Visualization

Status: Design (draft)
Project: Citadel
Audience: Architecture, Security, Platform, Operations, Frontend
Related: `distributed-attestation-mesh.md` (§5.3, §16, §17 — the control-plane /
dashboard spec this elaborates), `application-appraisal.md` (external control
plane consumes app results), `attestation-roadmap.md`,
`distributed-log-shipping-lthash.md`.

> This is the **observability + operator** layer that sits *above* the
> attestation mesh. The mesh (built: `tpm-core` + `citadel-mesh` +
> `citadel-agent`) decides trust locally and by witness quorum; this layer
> *aggregates, verifies, explains, and acts on* what the mesh already decides —
> it does **not** make trust decisions the mesh doesn't, and the mesh does not
> depend on it.

---

## 1. Purpose

Operators need to answer, across a fleet of 10–10,000+ nodes:

- Is the mesh healthy? Which nodes are trusted / degraded / suspicious / isolated?
- **What changed, and who agrees?**
- Can the evidence be reconstructed?
- What action should I take — and what did I (or someone) do?

`distributed-attestation-mesh.md` §5.1 places a **Dashboard/API** over a
**Control Plane** over the mesh, and §16–17 sketch the APIs and views. Nothing
of it is built. This document specifies it concretely, grounded in the data the
mesh **already emits**, and ordered so the first useful slice is small.

## 2. Goals / Non-goals

**Goals**
1. A **fleet-wide, verifiable** view of node trust, witness agreement, evidence
   durability, policy compliance, and a forensic timeline.
2. **Agreement-first** presentation (§17.4): never "node X is suspicious" alone,
   always "N of M independent witnesses report reason R; evidence is
   reconstructable; expected profile P, observed Q."
3. An **operator workflow** for signed, audited decisions (quarantine sign-off,
   policy publication) that enter the mesh as *signed policy inputs*.
4. Scale to 10k+ nodes; retain history for forensics.

**Non-goals**
1. **Not a root of trust.** The control plane (CP) cannot mint trust the mesh
   didn't independently reach. A compromised/malicious CP must not be able to
   make a node trusted, forge a quorum, or fabricate evidence — only (at worst)
   *withhold or misrender*, which is itself detectable (§8).
2. **Not in the trust path.** Agents keep attesting, witnessing, and quarantining
   with the CP offline. The CP observes and coordinates; it does not gate the
   protocol.
3. Not an evidence store — evidence lives erasure-coded in the mesh
   (`distributed-log-shipping-lthash.md`); the CP **indexes and verifies**
   reconstructability, it doesn't hold the bytes.

## 3. The cardinal principle — verify, don't trust

Every fact the dashboard shows is either (a) a **signed artifact the mesh
produced** that the CP **re-verifies itself**, or (b) **derived by the CP** from
such artifacts (and recomputable by anyone). The CP is a *verifier and
aggregator*, not an authority. Concretely:

- Witness verdicts, app results, reference manifests, and checkpoints are signed;
  the CP checks every signature against the (separately enrolled) node/authority
  keys before counting them.
- "Agreement" is **recomputed** from the individual signed verdicts — the
  dashboard shows the tally and lets you drill into each signed report.
- "Evidence reconstructable" is **proven** by the CP gathering ≥ threshold
  fragments and reconstructing (or verifying receipts + the erasure math), not
  asserted.
- Operator actions and published policy are **signed by the operator/authority
  key** and enter the mesh as inputs nodes evaluate, not commands they obey.

This is what lets a deployment "begin with a centralized control plane" without
the protocol "depending on absolute trust in it" (§5.3).

---

## 4. Architecture

```text
                    ┌───────────────────────────────────────────┐
                    │            Web Dashboard (SPA)             │
                    │  Fleet · Node · Agreement · Evidence ·     │
                    │  Quarantine · Forensics · Policy           │
                    └───────────────────────┬───────────────────┘
                                            │  HTTPS (read views + signed ops)
                    ┌───────────────────────▼───────────────────┐
                    │          citadel-control-plane             │
                    │  ┌──────────┐  ┌───────────┐  ┌─────────┐  │
                    │  │ Observer │→ │ Verify +   │→ │  Store  │  │
                    │  │  Node    │  │ Aggregate  │  │ (TSDB + │  │
                    │  │ (passive │  │ (agreement,│  │  state) │  │
                    │  │  mesh    │  │  durability│  └────┬────┘  │
                    │  │  member) │  │  rollups)  │       │       │
                    │  └────┬─────┘  └───────────┘   ┌────▼────┐  │
                    │       │         ┌───────────┐  │   API   │  │
                    │       │         │  Operator │←→│ (§16.2  │  │
                    │       │         │  workflow │  │  +16.3) │  │
                    │       │         └─────┬─────┘  └─────────┘  │
                    └───────┼───────────────┼────────────────────┘
            gossip (mTLS,   │   signed ops  │ (signed policy / quarantine
            verified)       │   gossiped    │  sign-off → mesh as inputs)
                    ┌───────▼───────────────▼────────────────────┐
                    │          Distributed Attestation Mesh       │
                    │  citadel-agent × N  (gossip · witness ·      │
                    │  attest · evidence shards · quarantine)      │
                    └─────────────────────────────────────────────┘
```

### 4.1 The Observer Node — the spine of the design

The CP's primary ingestion is a **passive mesh member**: a `citadel-mesh::Node`
the CP runs that enrolls, gossips, and **receives the same signed traffic every
node does** — but is **non-voting** (assigned no witness duties; its verdicts,
if any, don't count toward quorum) and holds no quarantine-enforcement role.

Why an observer node rather than a polling collector:

- It receives **first-hand, signed** `AttestResult` / `AppResult` /
  `ReferenceManifest` / `LogCheckpoint` / evidence receipts — the CP verifies
  signatures itself, so its data is as trustworthy as any node's.
- It rides the existing **mTLS transport** (E2) and gossip — no new agent
  surface to secure.
- It naturally sees **agreement** (every witness's verdict for a subject flows
  by gossip), evidence advertisements, and membership/liveness.
- It degrades safely: if the CP is down, the mesh is unaffected; when it returns,
  anti-entropy + re-challenge bring it current.

Polling agent `GET /v1/mesh/status` (already implemented) and a small **push
report** path supplement the observer for snapshots and for facts not gossiped.

### 4.2 Components
- **Observer node** — `citadel-mesh::Node` in observer mode (new flag) inside the
  CP process; feeds a verified event stream.
- **Verify + aggregate** — checks signatures, dedupes, computes agreement /
  durability / rollups, maintains current-state + time-series.
- **Store** — current state (per-node, per-subject agreement, quarantine cases)
  + an append-only time-series for forensics. Pluggable; default embedded.
- **API** — the §16.2 control-plane endpoints + §16.3 view payloads.
- **Operator workflow** — signed quarantine sign-off + policy publication,
  emitted into the mesh as signed inputs and recorded in an audit log.
- **Web dashboard** — a separate SPA consuming the view API.

---

## 5. Data sources — mapped to what the mesh already emits

The mesh already produces almost everything the dashboard needs; the CP mostly
**aggregates and verifies**. Mapping:

| Dashboard need | Existing source | Mechanism |
|---|---|---|
| Node liveness / trust | `membership` (`MemberUpdate`, `MemberRow`) | gossip piggyback; `GET /v1/mesh/status` |
| Per-witness verdicts → **agreement** | `GossipMessage::AttestResult` (`AttestationResult`: subject, verifier, result, reason_codes, confidence, policy_revision) | gossip |
| App appraisals + graded response | `GossipMessage::AppResult` (`AppAttestationResult`, signed) | gossip |
| Runtime (IMA) violations | shipped in `AttestationEvidence.ima_log`; verdict → `REFERENCE_DENIED` | via AttestResult |
| Reference values / policy revision | `GossipMessage::ReferenceManifest` (signed, chained) | gossip |
| Evidence durability | `EvidenceReceipt` (`LogFragmentAck`), `LogFragment` placement, `DigestAdvertisement` | gossip |
| Checkpoint / chain continuity | `GossipMessage::LogCheckpoint` (signed, quote-bound) | gossip |
| Quarantine cases | `QuarantineProposal` / `QuarantineVote` (`promotion.rs` / quarantine) | gossip |
| Audit chains | `reference_audit` / `app_audit` (`EvidenceChain`, hash-chained) | per-agent query |

**Gaps to close in the mesh (small):**
1. **`AttestationResult` is not self-signed** — its authenticity today rests on
   the signed gossip *envelope* (sender = verifier). For the CP to count and
   relay verdicts verifiably (and to audit them later), add a verifier signature
   to `AttestationResult` (mirroring `AppAttestationResult::verify`). *This is the
   one substantive mesh change this layer needs.*
2. **Observer mode** on `Node` (enroll + gossip, no witness assignment, no
   enforcement) — a config flag + skipping `run_witness_duties`.
3. Optional **agent push report** endpoint for snapshot state not gossiped (e.g.
   local config, agent version, last-seen self IMA digest).

---

## 6. Derived state — the aggregations that matter

### 6.1 Agreement (the central object, §17.4)
For each `(subject, policy_revision)` the CP keeps an **AgreementRecord**:
the set of signed `(verifier, verdict, reason_codes, confidence, tick)` it has
verified, the **assigned witness set** (recomputed via the same HRW
`witness::assign` the mesh uses), and therefore:
- `agree / total` (e.g. "37 of 40 witnesses report `PCR_MISMATCH`"),
- which assigned witnesses are **missing** a report (silence ≠ agreement),
- dissenters and their reasons,
- expected vs observed (the reason carries the PCR/profile delta).

The dashboard renders this verbatim — never a bare alert.

### 6.2 Fleet rollups (§17.1)
Trust-state histogram (Trusted/Degraded/Suspicious/Isolated/Probationary),
mesh-health %, evidence-durability %, quorum-health, current policy revision —
all recomputed from per-node verified state.

### 6.3 Evidence durability (§17.3)
Per evidence record: fragments advertised vs the erasure threshold, witness
receipts collected, and a **reconstruction check** (CP gathers ≥ threshold and
reconstructs, or verifies the receipts + placement). Chain continuity from the
signed checkpoints.

### 6.4 Forensic timeline (§17 "what changed")
Append-only, per-subject: enrollment → trust transitions (with the triggering
agreement record) → quarantine proposals/votes/enactment → operator actions →
recovery. Every entry links to the signed artifact behind it.

---

## 7. API (elaborating §16.2 / §16.3)

### 7.1 Control-plane endpoints (read)
```text
GET /v1/nodes                          # roster + current trust/liveness
GET /v1/nodes/{id}                     # NodeTrustView (§17.2)
GET /v1/nodes/{id}/attestations        # verified verdict history
GET /v1/nodes/{id}/agreement           # current AgreementRecord (§6.1)
GET /v1/nodes/{id}/evidence            # EvidenceDurabilityView (§17.3)
GET /v1/nodes/{id}/timeline            # ForensicTimelineView
GET /v1/mesh/health                    # FleetHealthView (§17.1)
GET /v1/policies/current               # active reference manifests / revision
GET /v1/agreement/{subject}/{rev}      # drill-down to each signed report
GET /v1/events?since=…                 # change feed (SSE/websocket for live)
```

### 7.2 Control-plane endpoints (write — signed, audited)
```text
POST /v1/policies                      # publish a signed ReferenceManifest → gossip
POST /v1/quarantine/operator-action    # operator sign-off (the gate severe scopes need)
POST /v1/enrollment/hello|claim        # enrollment workflow front door (proxied to mesh)
```
Every write requires an **operator/authority signature**; the CP relays it into
the mesh as a signed input and records it in its audit log. The CP holds no key
that can *decide* trust — only keys whose outputs nodes *evaluate*.

### 7.3 Dashboard views (§16.3) — each backed by §6 aggregations
`FleetHealthView` · `NodeTrustView` · `WitnessAgreementView` ·
`EvidenceDurabilityView` · `QuarantineView` · `ForensicTimelineView` ·
`PolicyComplianceView`. Payload shapes follow the §17 examples (Fleet/Node/
Evidence/Agreement blocks).

---

## 8. Security model

**Threats & properties (extends §18):**

- **Malicious/compromised CP.** Cannot create trust: nodes never accept a "node
  is trusted" assertion from the CP; trust is reached locally + by witness
  quorum. Cannot forge a quorum: agreement is the set of *signed* verifier
  reports; the CP can't synthesize them without verifier keys. Cannot fabricate
  evidence: durability is proven by reconstruction. **Residual power:** withhold
  or misrender — mitigated by (a) the change feed being reproducible from signed
  artifacts, (b) operators able to query agents directly, (c) multiple CP
  replicas reaching the same derived state.
- **Operator-action integrity.** Write paths are signed by the operator key and
  gossiped as inputs; a forged action fails signature check at the nodes. All
  actions are audit-logged (and ideally co-signed / quorum-gated for severe
  scopes, matching the mesh's operator-sign-off requirement).
- **Dashboard ↔ CP.** Operator auth (OIDC/mTLS) + RBAC; read vs operate split.
- **CP ↔ mesh.** The observer node uses the same mTLS + enrollment as any node;
  it is enrolled as **non-voting** so even a compromised observer can't sway
  quorum.
- **PII / exposure.** Evidence/IMA paths can be sensitive; the CP indexes
  metadata + verifies, and gates raw-evidence retrieval behind RBAC.

---

## 9. Storage & scale

- **Current state** (per-node, per-subject agreement, quarantine cases, policy):
  bounded by fleet size; in-memory + periodic snapshot, or embedded KV.
- **Time-series / forensic log**: append-only, retained per policy; the natural
  fit is a TSDB or an append-only table; partition by cluster/time.
- **10k+ nodes**: the observer-node + verify pipeline is the throughput concern
  (verdicts scale with witness_count × challenge rate). Mitigations: multiple
  observer nodes sharded by HRW subject-space; CP read-API horizontally scaled
  over shared store; sampling/rollup of steady-state "all-agree" verdicts,
  keeping full fidelity for disagreement/transitions.
- Evidence bytes stay in the mesh; the CP stores only indexes + verification
  results.

---

## 10. Implementation plan

New crate **`citadel-control-plane`** (Rust, axum + the existing
`citadel-mesh`/`citadel-agent`/`tpm-tls` building blocks) + a separate web SPA.

| Phase | Deliverable | Reuses / needs |
|---|---|---|
| **CP0** | `Node` **observer mode** (enroll, gossip, no witness/enforce) + **sign `AttestationResult`** | `citadel-mesh` (the one mesh change) |
| **CP1** | Observer-node ingestion → verify → current state; `GET /v1/nodes`, `/v1/mesh/health`; trust histogram | CP0; reuses gossip/membership |
| **CP2** | **AgreementRecord** + `/agreement` views (the §17.4 core) | `witness::assign`, signed verdicts |
| **CP3** | Evidence durability + reconstruction check; checkpoint chain continuity | `erasure`, receipts, checkpoints |
| **CP4** | Forensic timeline + audit-chain verification + change feed (SSE) | `EvidenceChain`, time-series store |
| **CP5** | Operator workflow: signed policy publish + quarantine sign-off → gossip; audit log | RVP (`rvp.rs`), quarantine path |
| **CP6** | Web dashboard SPA (all §16.3 views, agreement-first) | the view API |
| **CP7** | Scale/HA: sharded observers, replica read-API, rollup/retention | CP1–CP5 |

CP0–CP2 already deliver the headline value: a verifiable fleet view with the
agreement-first node drill-down. Everything before CP5 is **read-only** and
can't affect the mesh.

### 10.1 What already exists vs. new
- **Exists:** all the signed artifacts (verdicts, app results, manifests,
  checkpoints, receipts), membership/liveness, the agent `/v1/mesh/status`,
  witness assignment, erasure/reconstruction, audit chains, the RVP, mTLS.
- **New:** observer mode + `AttestationResult` signature (small, in-mesh); the
  `citadel-control-plane` crate (ingest/verify/aggregate/store/API); the SPA.

## 11. Open decisions
1. **Observer ingestion vs. push:** recommend observer-primary (verifiable),
   poll/push as supplements. Confirm.
2. **Store choice:** embedded (SQLite/`secure-log`?) vs. external TSDB — depends
   on retention/scale targets.
3. **Operator-action gating:** single operator signature vs. quorum/co-sign for
   severe scopes (the mesh already wants operator sign-off for severe quarantine).
4. **Frontend stack** and auth (OIDC vs. mTLS-only).
5. Whether the CP should also expose a **read-only TUI** (reuse `tpm-tui`
   patterns) for air-gapped/ops use before the SPA.

---

## 12. Summary

The mesh already decides trust and emits signed evidence of every decision. This
layer is a **verifying aggregator + operator console** on top: an observer node
that re-checks every signed artifact, computes **agreement** as the central
object, proves evidence reconstructability, and lets operators act through
signed inputs the mesh evaluates rather than obeys. It is explicitly *not* a root
of trust, and the mesh runs without it — so it can ship incrementally
(read-only CP0–CP4 first) and a centralized deployment stays honest to the
distributed trust model.
