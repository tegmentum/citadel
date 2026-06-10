# Citadel — in-tree completion plan

**Status:** Plan

The in-tree platform is feature-complete; this plans the **four remaining
buildable-now items** (no hardware / live infra). Ordered **quick-wins first**
(ascending risk/effort) so each de-risks the next. Each is built in the
established rhythm: pure core → tests → `fmt` + workspace `clippy -D warnings` →
commit (conventional, no Claude/emoji) → `act` in-container.

Everything else outstanding is the **deployment/hardware tier** (real TPM 1.2/2.0
devices, SP5 OptiPlex demo, live SPIRE/observability, the 3-VM concurrent
measured-boot mesh, the MSS8b driver in the live gossip loop) — gated on
infrastructure, explicitly **out of scope** here.

## Tracking

| # | Item | Crate | Effort | Depends on |
|---|------|-------|--------|-----------|
| P1 | ✅ MSS8b driver integration scenario | `citadel-mss` | ~0.5 d | MSS8a/b (done) |
| P2 | ✅ Persist + reclaim sealed shares (MSS8 D3) | `citadel-mss` | ~1 d | MSS8a (done) |
| P3 | Fact-gossip into the live mesh | `citadel-mss`→`citadel-mesh` test | ~1 d | FL1/FL2, AppRelay (done) |
| P4 | Threshold-BLS unbiasable beacon (MB hardening) | `citadel-beacon` | ~2–3 d | MB1–3 (done) |

**Suggested order:** P1 → P2 → P3 → P4 (compose-existing first; the new-crypto
dep last).

---

## P1 — MSS8b driver integration scenario

**Goal.** An end-to-end test that drives the full churn loop over composed
pieces, proving `decide_reshare` → `reshare_committee` actually rotates a working
committee (today MSS8a/b are unit-tested in isolation).

**Approach.** A harness/integration test (`citadel-mss/tests/churn_scenario.rs`):
build a `CustodyCommittee` + a real secret split into gen-0 shares; feed
`HolderLiveness` timelines and tick forward.

**Steps / asserts.**
1. All holders fresh → `decide_reshare` = `NoChange`; the committee still
   reconstructs the secret.
2. A holder transiently absent (< grace) → `NoChange` (the secret still
   reconstructs from survivors).
3. A holder durably-gone (> grace) → `Reshare{next, evicted}`; run
   `reshare_committee` → the gen-1 committee reconstructs the **same** secret, and
   the evicted holder's gen-0 share is fenced.
4. Trusted pool < k → `Escalate`.

**Risk:** low (composes done units). **Verify:** the new test + the existing suite.

---

## P2 — Persist + reclaim sealed shares (MSS8 D3)

**Goal.** A committee member persists its sealed share and reclaims it on
restart, so a **reboot is free** (no reshare needed) — and a stale-generation
share (the node was reshared out while down) is discarded on reclaim (fenced).

**Approach.**
- A `ShareStore` trait + an in-memory impl and a file/sqlite impl, persisting
  `{ secret_id, generation, sealed GenShare }` per held share.
- `reclaim(secret_id, current_committee)`: load the persisted share; keep it iff
  its generation **matches** the committee's current generation (D4 fence); else
  discard (the node was superseded while down) and re-enrol fresh.

**Steps / asserts.**
1. Persist a node's sealed gen-share; a fresh `ShareStore` instance loads it
   (models a reboot) → the share is present and unseals to the right gen-share.
2. After a reshare bumped the committee to gen+1, a node reclaiming a gen-0 share
   discards it (stale generation) — the zombie fence at reclaim time.
3. A quorum of reclaimed (current-gen) shares reconstructs the secret.

**Risk:** low (a store + load; reboot is simulated by a new store instance).
**Verify:** the store round-trip + fence tests.

---

## P3 — Fact-gossip into the live mesh

**Goal.** Run the fact protocol (FL) over the live mesh, not just the in-memory
library: a node broadcasts an `Assertion`, witnesses run their `FactChecker` and
emit `FactVote`s, and the `FactLedger` reaches `witnessed_true` over real gossip
— mirroring how TW2/CA2 wired tripwires/CA over `AppRelay`.

**Approach.**
- A thin driver (in `citadel-mss::facts`-side or a test helper): broadcast
  `FactMessage::Assert` on `FACT_TOPIC`; each witness drains it, runs a checker,
  broadcasts `FactMessage::Vote`; collect votes into a `FactAttestation`.
- A live harness test (`citadel-mss/tests/fact_gossip.rs`): a mesh of nodes, each
  with a software `FactChecker`, gossips an SBOM/patched assertion; a quorum of
  checking witnesses → `witnessed_true`; a false assertion → not witnessed.

**Risk:** low–medium (reuses `AppRelay` + the FL library; the checker is
software-modeled in the harness, like TW3's `SoftwareDetector`).
**Verify:** the live harness test (gossip → quorum attestation).

---

## P4 — Threshold-BLS unbiasable beacon (MB hardening)

**Goal.** Make the beacon **unbiasable even against a colluding signing quorum**
— a true unique-per-input VRF. Today's FROST/Schnorr beacon (MB1) is unpredictable
+ single-node-unbiasable, but a colluding threshold could grind nonces; a
**threshold-BLS** signature is *deterministic and unique* per message, so the
beacon value is a fixed function of `(round ‖ prev)` and cannot be ground.

**Approach.**
- Add a vetted threshold-BLS dependency (candidate: `blsttc` / a `blst`-based
  threshold crate — pick one with a maintained, reviewed API; record the choice +
  why).
- A `bls` module in `citadel-beacon`: threshold keygen, threshold-sign, verify.
- Abstract the beacon over a scheme: a `BeaconScheme` trait with the existing
  FROST impl and the new BLS impl, so deployments choose (FROST already shipped;
  BLS is the unbiasable upgrade). `BeaconRound`/`value`/chaining are
  scheme-generic.

**Steps / asserts.**
1. `bls` keygen/sign/verify round-trips; a threshold reconstructs a valid group
   signature.
2. **Determinism:** two independent signings of the same `(round, prev)` produce
   the **same** signature (and value) — unlike FROST — proving unbiasability (no
   nonce to grind).
3. Chain + `verify_chain` + `nonce_for` work over the BLS scheme.

**Risk:** medium — a new pairing-crypto dependency (audit/selection care); the
scheme abstraction touches `citadel-beacon`'s core types. Largest of the four.
**Verify:** determinism + verification tests; `act` (new dep builds in-container).

---

## Out of scope (deployment/hardware tier)

TPM 1.2 device binding (TrouSerS), real hardware TPM 2.0, SP5 OptiPlex demo +
live SPIRE plugin loading, the live observability pipeline, the 3-VM concurrent
measured-boot mesh, the mesh-primitive phase-3 tails (FL3 CP API/dashboard, CA3
holder-pinning/pipeline, TW3 eBPF hooks, FED3 multi-mesh), and wiring the MSS8b
driver into the live gossip/epoch loop. Each is documented in its own roadmap and
needs running infrastructure, not more in-tree code.
