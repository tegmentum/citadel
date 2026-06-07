# Citadel: Application-Level Appraisal & Graded Response

Document Version: 0.2
Status: Phase 1 (report-only) **built**; Phases 2–4 planned
Project: Citadel
Audience: Architecture, Security, Platform, Runtime Engineers
Related: `distributed-attestation-mesh.md`, `measured-state-transitions.md`,
`event-log-attestation.md`, `distributed-log-shipping-lthash.md`, `mma-upgrade.md`,
`attestation-roadmap.md`

> Fills a real asymmetry in the current design: a **TPM / measured-boot**
> anomaly drives the full distrust→quarantine machinery, but a **registered
> application** that fails appraisal has *no* detection path and *no* response
> path. This doc adds app-scoped appraisal, a **graded** (not all-or-nothing)
> response, and a clean detect/remediate split — and in doing so finally
> enforces the two quarantine scopes that are today declared but inert.

---

## 1. The asymmetry today

When the **platform** misbehaves, the path is concrete and automatic:

```
bad quote / PCR_MISMATCH / REFERENCE_* / equivocation
   → Verdict::Fail (attest.rs)
   → witnesses gossip → aggregate_trust → TrustState::Suspicious (node.rs)
   → quarantine proposal + vote (quarantine.rs)
```

When a **registered application** on an otherwise-healthy node misbehaves, there
is **nothing**. Concretely, in the code:

* `AttestationEvidence.agent_measurement: Option<String>` exists but is **never
  appraised** — no policy reads it (`attest.rs`).
* `ReasonCode::AgentVersionDeprecated` and `RoleNotAuthorized` are **declared
  but unused**.
* `QuarantineScope::BlockWorkloadScheduling` and `CredentialRevoke` are
  **declared but inert** — they grade the quorum needed to enact, but nothing
  reads them to actually change runtime behaviour (only `restricts_voting`,
  `restricts_evidence_holding`, and `isolates` are enforced).
* App/runtime *measurement* (IMA, `attestation-roadmap.md` C1) is not built, so
  there is no signal to appraise in the first place.

So the answer to "what do we do if a registered application doesn't pass?" is,
today: **we don't detect it, so we do nothing.** This doc designs the missing
half.

## 2. Principle: proportionate response

A platform compromise and a single drifting application are different blast
radii and deserve different instruments:

* **Platform evidence fails** (TPM, boot state, agent self-measurement) → the
  *machine* is untrustworthy → node-scoped distrust / quarantine, as today.
* **A registered app fails** → *that app* is untrustworthy, the node may be
  fine → an **app-scoped** verdict and a **graded** response; escalate to
  node-level only on policy threshold (many apps failing, a critical app, or
  repeated failure).

Quarantining a whole machine because one app drifted is too blunt. The design
keeps the blunt instrument for "the platform is compromised" and adds a
proportionate one for "an app drifted."

## 3. What is a "registered application"

A first-class, independently-appraised workload identity — not today's opaque
`agent_measurement` string. Minimum model:

```rust
struct AppId { name: String, instance: Option<String> }   // e.g. "billing-api" / pod uid

struct AppMeasurement {
    app: AppId,
    /// What was measured (IMA file/exec digest, or a self-reported, signed
    /// measurement); the *binding* to the platform is via the PCR the runtime
    /// log extends (PCR 10 for IMA) — so app evidence inherits the quote's
    /// integrity (event-log-attestation.md replay==quote).
    digest: Vec<u8>,
    version: Vec<u64>,
    role: String,
    timestamp_tick: u64,
}
```

App measurements ride the existing evidence (alongside the quote) and, for IMA,
are validated by event-log replay — so an app claim cannot be forged without
breaking the quote binding. Self-reported app measurements that are *not*
PCR-bound are accepted only as advisory (lower confidence), mirroring the §3
"event data is not PCR-bound" rule in `event-log-attestation.md`.

## 4. App-scoped appraisal

Reuse the appraisal vocabulary already built for measured state:

* **Allowed app states** — per `(app.name, role)`, a set of accepted digests /
  versions, gated by the same `FleetArtifactPolicy` (approved channel, version
  baseline, denylist) and authorized by the same signed `ReferenceManifest`
  path. An app upgrade is a manifest, revocation is a denylist entry — the whole
  `measured-state-transitions.md` machinery applies, just keyed by app instead
  of PCR.
* **Outcome** is app-scoped, not node trust:

```rust
enum AppVerdict { Healthy, Degraded, Failed, Unknown }   // mirrors Verdict
```

New reason codes (filling the dormant ones + additions):
`APP_VERSION_DEPRECATED` (rename/realize `AgentVersionDeprecated`),
`APP_ROLE_NOT_AUTHORIZED` (realize `RoleNotAuthorized`),
`APP_MEASUREMENT_UNKNOWN`, `APP_MEASUREMENT_REVOKED`.

## 5. Response: report first, then grade, then maybe escalate

The user's instinct — "report it so something else can remediate" — is the
right default. Three layers:

### 5.1 Report (always)
Every app appraisal produces a **signed `AppAttestationResult`** (mirrors
`AttestationResult`: subject node, app, verdict, reason codes, confidence,
tick). It is:
* **recorded** in the evidence chain — a new `RecordType::AppAttestationResult`
  (alongside `AttestationResult`), so it is durable, hash-chained, and
  preserved by the erasure vault like all other evidence; and
* **gossiped**, so an external control plane (orchestrator/operator) sees it.

This alone answers the question: a failing app is **always** reported as durable,
attributable evidence — detection is decoupled from remediation.

### 5.2 Grade (app-scoped enforcement — wires the inert scopes)
A quorum-decided app response, reusing the `quarantine.rs` proposal/vote engine
but **scoped to the app**, finally giving the two dormant scopes teeth:

| App condition | Scope | Effect (now enforced) |
|---|---|---|
| version deprecated / advisory | `ObserveOnly` | raise attestation frequency for the app |
| unknown / unauthorized measurement | `BlockWorkloadScheduling` | the scheduler must not place / restart this app here |
| revoked (CVE) / role violation | `CredentialRevoke` | the app's mesh-issued credentials are revoked |

These map onto the existing `QuarantineScope` severity ladder and its quorum +
operator-gate requirements (`CredentialRevoke` already requires operator
sign-off). The change is (a) an app-scoped target, and (b) enforcement hooks
that read the scope — `block_workload_scheduling(app)` consulted by whatever
schedules work, and `revoke_credentials(app)` consulted by credential issuance.

### 5.3 Escalate (to the node) only on policy threshold
App failures roll up to node trust only when policy says the *platform* is
implicated, e.g.: a critical-tagged app fails; ≥K distinct apps fail on one
node; or the same app fails after remediation N times. Then — and only then —
the node goes `Suspicious` via the existing path. Default: app failure does
**not** touch node trust.

## 6. Detect / remediate split

Citadel is the **trustworthy detector and evidence vault**, not the remediator:

```
Citadel mesh                         External control plane
────────────                         ──────────────────────
appraise app  ─► AppAttestationResult ─(gossip/API)─►  consume verdict
record (evidence chain)                                 restart / redeploy / cordon
enforce graded scope (block sched / revoke creds)       (acts on the report)
```

Remediation (restart the app, redeploy a clean image, drain the node) is the
orchestrator's job, reacting to the gossiped/recorded verdict and the enforced
scope. Citadel guarantees the signal is **authentic, attributable, and durable**;
it does not itself restart workloads. (An operator-driven remediation can be
recorded as a `RecordType::OperatorAction`, closing the audit loop.)

## 7. Interaction with existing mechanisms

* **Probation/quarantine (node):** unchanged for platform evidence; app scopes
  are a parallel, app-keyed track that does not freeze node trust.
* **Measured-state transitions:** app allow-lists are just `ReferenceManifest`s
  keyed by app — graceful app rollouts, revocation, and quorum promotion come
  for free.
* **Event-log / IMA (C1):** the *measurement source* for non-self-reported app
  evidence; this doc is the appraisal+response layer on top of it.
* **MMA (agent self-measurement, PCR 14):** Citadel's own agent is the first
  "registered application" — its PCR-14 measurement appraised on this path
  (`mma-upgrade.md` tie-in) means the agent policing apps is itself policed.

## 8. Threat-model notes

* **Forged app claim:** rejected unless PCR-bound (IMA replay==quote); a
  self-reported claim is advisory-only and cannot raise trust.
* **A compromised app suppressing its own measurement:** IMA is append-only into
  PCR 10 and the log is shipped/checkpointed, so a missing expected measurement
  is itself a signal (absence detection — a later refinement).
* **A compromised node lying about an app:** caught by the same witness-quorum
  aggregation that governs platform verdicts — app verdicts are cross-checked,
  not taken from one observer.
* **Out of scope (unchanged):** majority capture; TPM physical extraction.

## 9. Phasing

* **P1 — report-only. ✅ Built.** `application.rs`: `AppId` / `AppMeasurement` /
  `AppVerdict` / `AppReasonCode` / `AppPolicy::appraise` / signed
  `AppAttestationResult`. `node.rs`: `set_app_policy` / `appraise_app` /
  `report_app` (appraise → record in an `app_audit` chain + latest-per-app →
  gossip) / `on_app_result` (verify sig → record); `GossipMessage::AppResult`;
  `RecordType::AppAttestationResult`. Realizes `AppVersionDeprecated` /
  `AppRoleNotAuthorized` / `AppMeasurementUnknown` / `AppMeasurementRevoked`,
  and split `FleetArtifactPolicy` into `below_baseline` (deprecated, soft) vs
  `is_denied` (revoked/channel, hard). **Node trust is untouched** — a failing
  app is reported fleet-wide but does not quarantine the machine. Tests:
  `application.rs` units + e2e (`tests/application.rs`): healthy report
  propagates + audited; a *failing* app is reported but the node stays Trusted;
  self-reported measurements are advisory.
* **P2 — graded enforcement.** App-scoped quarantine proposals/votes; enforce
  `BlockWorkloadScheduling` / `CredentialRevoke` via new hooks
  (`block_workload_scheduling`/`revoke_credentials`). Wires the inert scopes.
* **P3 — escalation policy.** Roll-up thresholds (critical app / ≥K apps /
  repeat-after-remediation) to node trust.
* **P4 — real app measurement.** Bind to IMA (depends on `attestation-roadmap.md`
  C1) for non-self-reported, PCR-bound app evidence; absence detection.

P1 + P2 are software-only and deliver the answer to the original question
(report always; graded app-scoped action; node-quarantine reserved for platform
compromise). P4 is gated on IMA/runtime measurement.

## 10. Open questions

* App identity binding: how an `AppId` is authenticated to a node (mesh-issued
  workload credential vs. IMA-measured path) — affects P1 vs P4 ordering.
* Whether `AppAttestationResult` rides the existing `AttestationEvidence` or a
  separate gossip message (leaning separate, to keep platform attestation lean).
* Escalation defaults (the K / N thresholds) — operator policy, not hardcoded.
* Credential revocation mechanism — depends on whether app credentials are
  mesh-issued (then `CredentialRevoke` is internal) or external (then it is a
  reported action for the control plane).
