# Mesh Integration Roadmap

Status: Plan
Related: `distributed-attestation-mesh.md` (Phases 0–6, implemented),
`distributed-log-shipping-lthash.md`, `mma-upgrade.md`

The distributed attestation mesh protocol core (Phases 0–6) is implemented
and tested in `crates/citadel-mesh` as a **network-free, deterministic**
library plus an in-process harness, with real-vTPM attestation validated.
Four pieces remain to turn it into a running product. This document plans
them: scope, approach grounded in the current code, risks, testing, and
sequencing.

| # | Item | Goal | Unblocks | Rough effort |
|---|------|------|----------|--------------|
| 1 | Transport over `tpmd` | separate processes form a real mesh | live deployment | 3–5 d |
| 2 | AK/EK endorsement chain | bind the AK to real hardware (`AK_UNTRUSTED`) | trustworthy roots | 3 d (vTPM) → ~2 wk (full) |
| 3 | LtHash reconciliation | detect/repair log divergence at scale | forensic durability | 1–2 wk |
| 4 | `tpmd` real backend | run on a real TPM (TLS key, attestation) | items 1, 2 end-to-end | 3–5 d |

---

## Item 1 — Transport wiring (HTTP) — FIRST CUT DONE

Implemented in `crates/citadel-agent`: a `Transport` seam, an async actor
that owns one `citadel_mesh` `Node` (command channel + interval ticks,
outbox drained to the transport), a `ChannelSwitchboard` (in-process) and an
`HttpTransport` (`POST /v1/gossip`), the `GET /v1/mesh/status` endpoint, and
a `citadel-agent` bin (seed-based peer addressing via `CITADEL_PEERS`).
Tests: real tokio agents form a mesh and drive a stopped node
`Alive → Faulty` over the channel transport, and three agents converge over
real localhost HTTP sockets. The protocol core in `citadel-mesh` is
unchanged. Remaining on this item: mTLS peer auth (reuse the `tpmd`
TPM-held-key TLS work), membership-propagated addresses (vs. the static seed
map), and hosting the same router inside `tpmd`.

**Goal.** Run each node as a process that gossips with peers over the
network, reusing the `citadel_mesh::node::Node` tick/deliver core unchanged.

**Approach.**
- Introduce a `Transport` seam in `citadel-mesh`: `trait Transport { fn
  send(&self, to: NodeId, env: GossipEnvelope); }`. The harness already is an
  in-memory transport; add an `HttpTransport` that resolves `NodeId → URL`
  from membership and POSTs the (serde-`Serialize`) envelope.
- Give `Member`/`MemberUpdate` an **address** (URL/host:port); seed it from a
  peer/seed list. (Today membership carries only liveness + key.)
- A small async **runtime/actor** (tokio) owns one `Node`: a `tokio::interval`
  fires `node.tick()`; an inbound channel feeds `node.deliver(env)`; after
  each tick/deliver, drain `node.take_outbox()` and dispatch via `Transport`.
- Add agent endpoints. Because every mesh message (PING/ACK, attestation,
  enrollment-, quarantine-bearing messages) already rides inside a signed
  `GossipEnvelope`/`GossipMessage`, the core needs essentially **one**
  endpoint: `POST /v1/gossip` (verify + `deliver`). Add `GET /v1/mesh/status`
  for the dashboard. Host these in `tpmd` (or a new `citadel-agent` bin that
  embeds the same router).

**Key files.** `citadel-mesh`: new `transport.rs` (trait + http impl), `Member`
address field; `tpmd`: `POST /v1/gossip` handler; new runtime/actor module.

**Risks / open questions.**
- The harness assumes acks **settle synchronously within a step**; over a real
  network they don't. Suspicion/probe timeouts must be retuned to wall-clock
  RTT (the SWIM params already exist in `NodeConfig` — make them durations).
- Backpressure / outbox draining under load; lost determinism (fine for prod —
  the harness stays the deterministic test oracle).
- Envelope auth is already end-to-end (Ed25519); mTLS (item 4 / existing
  `tpmd` TLS) adds transport-level peer auth.

**Testing.** A tokio integration test spins up N agents on localhost ports
(mock backend) and asserts membership convergence + witnessed trust — the
Phase 0/2/3 acceptance, now over sockets.

**Can start now** (mock backend); independent of items 2–4.

---

## Item 2 — AK/EK endorsement chain — FIRST CUT DONE

Done (mesh enforcement layer): `Endorsement` (an endorser signs
`(subject, ak_public)`), `TrustAnchors` (the trusted endorser set), and
`AttestationEvidence.endorsement`. `Attestor::verify` now flags
`AK_UNTRUSTED` (→ `Fail`) when anchors are configured and the quote's AK
lacks a valid endorsement from a trusted endorser; `enrollment` refuses such
a candidate (`AdmissionReason::AkUntrusted`). Empty anchors keep the
early-phase self-certifying behaviour, so all prior tests pass. Tested
(`tests/endorsement.rs` + units): an endorsed mesh converges trusted; an
unendorsed node is `AK_UNTRUSTED`/suspicious cluster-wide; an unendorsed
candidate is refused; untrusted-endorser and wrong-AK endorsements are
rejected.

Remaining (the hardware half): produce the endorsement from real hardware —
map `tpm_core::vtpm_credential` (a hw-TPM signing a vTPM identity) so it
covers the *per-quote AK* (credential activation / AK-in-statement), and
validate a manufacturer **EK certificate** chain as the anchor. This is the
deferred Step (b); the enforcement seam above is ready for it.

**Goal.** Close the `AK_UNTRUSTED` gap: a verifier accepts a quote only if the
attestation key chains to an **endorsed** key rooted in real hardware, so a
synthesized AK (today the AK public is taken from the quote) is rejected.

**Approach.**
- Reuse the existing `tpm_core::vtpm_credential` (`VtpmCredential` /
  `VtpmIdentity`): a hardware TPM signs an endorsement statement over a vTPM
  identity (today produced by `tpm vtpm provision`, gated on `--features
  tpm-hw`). This is the ready-made trust anchor for vTPM nodes.
- Backend: add `endorsement()` / `ak_credential()` to `TpmBackend` returning
  the AK's credential/cert (vTPM: the `VtpmCredential`; hardware: the EK cert
  from NV + a TPM2 **credential-activation** `MakeCredential`/`ActivateCredential`
  binding AK↔EK).
- Evidence: populate `AttestationEvidence.ak_certificate_or_chain` (already in
  the design's bundle, currently omitted) and have `Attestor::verify` validate
  it against a configured **trust-anchor set** (the RATS *Endorser* /
  Reference-Value-Provider role). On failure → `ReasonCode::AkUntrusted` →
  `Fail`. Wire the same check into `enrollment::assess_claim`.

**Key files.** `tpm-core` backend traits + `vtpm_credential.rs`; `citadel-mesh`
`attest.rs` (anchor set + endorsement check), `types.rs` (carry the chain),
`enrollment.rs`.

**Risks.** Full hardware path (manufacturer EK X.509 roots + credential
activation) is a meaty TPM flow. **Scope in two steps:** (a) vTPM credential
chain first (the machinery exists), (b) hardware EK cert + activation later.

**Testing.** vTPM-gated: provision a credential, enroll/attest with it, assert
a node with a missing/forged credential is `AK_UNTRUSTED` and refused.

**Effort.** ~3 d for the vTPM-credential cut; ~2 wk for the full hardware path.
**Depends on** item 4 (a backend that exposes the EK/credential).

---

## Item 3 — LtHash log-shipping & reconciliation

**Goal.** Implement `distributed-log-shipping-lthash.md`: nodes accumulate
their measurement log into windowed LtHash roots, advertise them, and
reconcile **only the differing windows** — detecting divergence and
equivocation at fleet scale.

**Approach.**
- New `citadel-mesh` module(s) (e.g. `logship.rs`) for the canonical
  `EventRecord`, monotonic sequence numbers, and **windowed LtHash
  accumulators** (`EventElement = H(node_id ‖ boot_id ‖ seq ‖ payload_hash)`).
- Depend on **`lthash-rs = "1.0.1"`** (native; the sibling `~/git/lthash-wasm`
  is the sandboxed/JS variant). Map: accumulate = `union`/add, supersede =
  `difference`, window/subrange root = snapshot, divergence = snapshot
  inequality (per the design's §8 mapping table).
- Protocol: a periodic `DigestAdvertisement` (window_id, max_seq, root) via a
  new `GossipMessage` variant; on a mismatch, binary-search subranges
  (sub-LtHash snapshots) to isolate the divergent range, then transfer the
  missing `EvidenceRecord`s.
- Integrate with what exists: divergent/missing records feed Phase 4
  (`erasure`/`evidence` holders, `ReconstructionProof`); **equivocation**
  (two roots at one `(boot, seq)`) → `CHECKPOINT_EQUIVOCATION` → Phase 3
  `Suspicious`.

**Key files.** `citadel-mesh` new `logship.rs` (+ `evidence`/`erasure` reuse),
gossip message variant; `lthash-rs` dependency.

**Risks.** Window sizing + reconciliation depth; keep the **set-homomorphic**
LtHash (order-independent) distinct from the **ordered** `EvidenceChain`
(§12) — they answer different questions (membership vs. sequence).

**Testing.** Unit/harness: two logs diverging by a few records reconcile
transferring only the diff; equivocation is detected; durability proof after
reconciliation. Buildable in the harness before transport.

**Effort.** ~1–2 wk. Largely **independent** (engine + protocol testable in
the harness); becomes truly distributed once item 1 lands.

---

## Item 4 — `tpmd` real backend — DONE

Done: the vTPM backend was extracted from the `tpm` bin into its own crate
`crates/vtpm-backend` (the bin now aliases it behind its `vtpm` feature; the
moved tests, incl. the two mesh+vTPM ones, came along). `tpmd` gained a
`vtpm` feature and selects its backend at runtime via `TPMD_BACKEND`
(`mock` | `vtpm`); `vtpm` reads `TPM_VTPM_COMPONENT` and persists state at
`TPMD_VTPM_STATE` (default `<store>.tpmstate`), constructed as the shared
`Arc<dyn TpmBackend>` behind both the API and the TLS layer — so the TPM-held
TLS key (item-less work, already implemented) is now usable end-to-end.
`citadel-agent` could adopt the same `vtpm-backend` dep as a follow-up.

**Goal.** Let `tpmd` (and the agent) run on a real TPM so the TPM-held TLS key
(already implemented) and real attestation work end-to-end — today `tpmd`
hardcodes `MockBackend`, which cannot produce real signatures.

**Approach.**
- The hardware backend exists (`tpm_core::backend::hardware` behind
  `tpm-hw`), but the **vTPM backend lives in the `tpm` bin** (`src/vtpm_bridge.rs`),
  so `tpmd` cannot use it. **Extract** `vtpm_bridge` into a library crate
  (`crates/vtpm-backend`) depended on by both the bin and `tpmd` (it already
  pulls `vtpm-wasm` + wasmtime).
- Backend selection by env in `tpmd::run`: `TPMD_BACKEND=mock|vtpm|device`
  (`vtpm` reads `TPM_VTPM_COMPONENT` + a state path; `device` needs
  `tpm-hw`). Construct the chosen backend as the shared `Arc<dyn TpmBackend>`
  (the Arc refactor is already done for the TLS work).

**Key files.** new `crates/vtpm-backend` (moved from `src/vtpm_bridge.rs`),
`tpm` bin re-point, `tpmd::run` backend selection, workspace `Cargo.toml`.

**Risks.** Mechanical but sizeable move (~1800 lines + the vTPM tests, the
`vtpm-wasm`/wasmtime deps, feature plumbing). Recommend **vTPM (Option B)**
over hardware-only so it is testable in CI with the published component.

**Testing.** `tpmd` integration test with `TPMD_BACKEND=vtpm` +
`TPM_VTPM_COMPONENT`: create/sign a key over HTTP, and the TLS-from-TPM
handshake end-to-end against a real vTPM key.

**Effort.** ~3–5 d. **Unblocks** items 1 (real keys on the wire) and 2 (EK).

---

## Sequencing

```text
now ─┬─ Item 1 (transport, mock backend)         ── independent, highest leverage
     └─ Item 3 (LtHash engine in the harness)    ── independent

then ── Item 4 (extract vTPM → tpmd real backend) ── unblocks real keys

then ── Item 2 (endorsement on the real backend)  ── closes AK_UNTRUSTED
        + converge: items 1+3+4 into a real multi-process mesh with real
          TPM keys and LtHash reconciliation
```

Recommended start: **Item 4 first** if the priority is a real end-to-end
demo (it underpins 1 and 2); **Item 1 first** if the priority is proving the
distributed protocol over the network (mock keys are fine to start). **Item 3**
runs in parallel either way. **Item 2** is last — it depends on a real
backend (item 4) and hardens, rather than enables, the running system.

Each item ships behind its own tests and leaves the deterministic harness as
the regression oracle; none requires changing the Phase 0–6 protocol core.
