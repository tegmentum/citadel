# Citadel — mesh primitives roadmap

**Status:** Plan

The security mesh's core primitive is **witnessed quorum over hardware-rooted,
categorical trust** — nodes attest each other, assigned witnesses vote, and a
quorum produces *signed* decisions, with quarantine + erasure-coded evidence on
compromise. On top of that sit three reusable mechanisms already built:

- the **release protocol** — request → assigned-witness vote → signed
  authorization, lease-bound, deny-at-renewal (`citadel-mesh::release`, MSS);
- **threshold crypto** — Shamir custody + FROST signing with DKG, carried over
  gossip (`citadel-mss::{threshold,tsig,session}`, MSS6/6b);
- the **generic gossip channel** + quarantine — `AppRelay` (opaque app messages)
  and the propose→vote→tally→enact quarantine flow.

This document tracks the next set of primitives that ride on those. Each is a
*new* surface — not a restatement of MSS / SPIFFE / observability — and each is
scoped to reuse the machinery above rather than reinvent it. The house style
holds: reuse-first, categorical trust (never a numeric score), honest scoping of
what's testable in-tree vs. deployment.

## Tracking

| # | Primitive | Crate (proposed) | Rides on | Priority | Status |
|---|-----------|------------------|----------|----------|--------|
| MB | Mesh randomness/freshness beacon | `citadel-beacon` | FROST/DKG, AppRelay | **1 (foundational)** | ✅ MB1–MB3 done |
| CAP | Continuously-earned capabilities | `citadel-caps` | release protocol, leases | **1 (unifying)** | ✅ CAP1–CAP3 done |
| FL | Witnessed fact/assertion ledger | `citadel-facts` | verdict quorum, reference manifests, audit chain | 2 (broadest) | 🔨 FL1–FL3 (selector+rollup; durable surface = deploy) |
| CA | Mesh-operated signing service / threshold CA | `citadel-ca` | FROST signing, trust gate | 2 | 🔨 CA1–CA3 (rotation; holder-pinning/pipeline = deploy) |
| TW | Distributed tripwires / honeytokens | `citadel-tripwire` | AppRelay, quarantine | 3 | 🔨 TW1–TW3 (adapter trait; real hooks = deploy) |
| FED | Cross-mesh federation / trust bridging | `citadel-federation` | trust bundles, SPIFFE federation | 3 (strategic) | 🔨 FED1–FED2 done |

**Suggested order:** MB + CAP first (foundational + unifying, both nearly free
given FROST and the release protocol); then FL (broadest product surface) and CA;
then TW and FED.

---

## MB — Mesh randomness/freshness beacon

The one foundational thing the mesh still lacks: a shared, unforgeable notion of
*now* and *fresh*. A periodically-produced, quorum-signed value
`beacon[round] = thresholdSign(round ‖ prev)` gives every node an agreed,
unpredictable anchor without trusting any single clock or RNG.

**Unlocks:** replay-proof challenges (verifier nonces derive from the beacon, not
a local clock), synchronized lease/epoch boundaries (MSS leases + SVID renewals
tick off the same round), fair witness sampling, and TPM-rooted leader election.

**Design calls**

- **MB-C1 — verifiable, not just agreed.** The beacon is a *threshold signature*
  over the round (FROST/BLS), so any node verifies it against the group key
  without re-running consensus — and it's unpredictable before the round closes
  (no single node can bias it). Reuses MSS6b's FROST/DKG directly.
- **MB-C2 — chained for freshness ordering.** `beacon[n]` commits to `beacon[n-1]`,
  so a beacon value proves "at least as recent as round n" — the freshness anchor
  other subsystems quote instead of a wall clock.
- **MB-C3 — liveness-degrading, not halting.** If a round can't reach threshold
  (partition), nodes fall back to the last signed beacon + a documented staleness
  bound, rather than blocking — the mesh stays available, freshness just ages.

**Phases**

| Phase | Scope |
|-------|-------|
| MB1 | ✅ done. `citadel-beacon`: `BeaconRound::{produce,verify,value,digest,nonce_for}` (threshold-sign `round ‖ prev` via FROST), `next_round`, `verify_chain`. Tests: rounds chain + verify; output unpredictable + single-node-unbiasable; tamper breaks verify/chain; nonces freshness-bound + domain-separated. |
| MB2 | ✅ done. `BeaconState` (per-node driver: adopt newest-verified, monotonic + gap-tolerant; `ingest` from drained AppRelay payloads; `value`/`nonce_for`) + `BEACON_TOPIC` + round serde. Live harness test: a holder broadcasts a round over AppRelay → every peer adopts the same verified value + freshness nonce. |
| MB3 | ✅ done. `Challenge` (round-bound nonce) + `BeaconRound::challenge`/`BeaconState::challenge` + `challenge_fresh` (a stale-round answer is a detectable replay) + `lease_active` (the canonical beacon-round lease predicate `citadel-caps` already uses). Tests: challenges are replay-proof across rounds + stale beyond the age window; state issues from the current round; lease expires by round. MSS/SVID/attestation adopt these helpers (integration). |

---

## CAP — Continuously-earned capabilities

MSS gates *secrets*; SPIFFE gates *identity*. The unifying primitive is gating
**any privileged action** on current mesh trust: a node requests a capability
("may deploy", "may write prod", "may join as a control node"), assigned witnesses
vote on its live trust, and the quorum issues a short-lived, **attenuable,
lease-bound capability token** (macaroon/biscuit-style — delegatable only
downward, never upward).

**Unlocks:** authorization-as-continuously-earned across the whole system, not
just secrets/identity; automatic revocation at renewal (the deny-at-renewal model
already proven in MSS); a single audited place where "who may do what, right now"
is decided by the mesh.

**Design calls**

- **CAP-C1 — capabilities are the release protocol with a token payload.** The
  request→witness-vote→signed-authorization flow is exactly MSS's; swap the
  payload from "unseal a secret" to "mint a signed capability token". Reuse
  `citadel-mesh::release` rather than a parallel protocol.
- **CAP-C2 — attenuation only narrows.** A holder may delegate a subset/caveat of
  its capability (shorter TTL, narrower scope) but never broaden it — verified by
  a caveat chain, like macaroons. The mesh quorum is the only issuer of *new*
  authority.
- **CAP-C3 — lease-bound, deny-at-renewal.** Capabilities are short-lived and
  renewed by re-running the vote, so a node whose trust dropped loses the
  capability at the next renewal (kept it mid-lease) — identical to MSS C4.
- **CAP-C4 — categorical-trust gated, freshness-bound (MB).** Issuance requires the
  requester `Trusted` (or a class-specific tier, à la MSS7 bootstrap); the token's
  freshness is bound to the beacon round (MB), so a replayed token expires by
  round, not just by clock.

**Phases**

| Phase | Scope |
|-------|-------|
| CAP1 | ✅ done. `citadel-caps`: `Capability` (scope/holder/beacon_round/lease) + `Caveat` (ExpiresAtRound/ScopePrefix/BoundToHolder); `mint`/`attenuate`/`verify` (signature chain, only-narrows) + `authorizes` (scope + lease freshness + expiry + holder). Tests: mint→authorize within scope+lease; attenuation narrows (broadening rejected); tamper + wrong-signer rejected; holder binding. |
| CAP2 | ✅ done. `capability_secret_id(holder, scope)` makes a capability a mesh-released class; `grant(authority, capability, quorum, auth, eligible)` mints **only** on a satisfied ReleaseAuthorization (reuses `release`, gates like MSS `open`). Tests: grant gated on quorum (below quorum / wrong scope refused); live harness — a Trusted node is authorized, a compromised one denied. |
| CAP3 | ✅ done. `Pep` (holds the issuer key; `authorize` → `Decision::{Allow,Deny(reason)}` with structured reasons: BadToken/OutOfScope/LeaseExpired/Expired/WrongHolder) + `guard` (runs an action only behind a valid token). Test maps a control-plane-write gate onto a `cp:write:policy` capability end to end. |

---

## FL — Witnessed fact/assertion ledger (the mesh as a notary)

Attestation verdicts are one instance of a general pattern: the quorum verifies a
*checkable claim* and signs the result. Generalize it so the mesh can reach signed
consensus on **any** evidence-backed fact — an SBOM hash, "CVE-2024-x is patched
here", a config digest, a compliance control's state.

**Unlocks:** supply-chain + compliance attestation ("this fleet is unanimously
patched, witnessed and signed"); policy that gates on facts beyond PCRs; a
verifiable, hardware-rooted notary.

**Design calls**

- **FL-C1 — a fact is a typed, checkable claim + its evidence.** `Assertion {
  subject, predicate, evidence_ref }`; a witness votes APPROVE only if it can
  *independently check* the evidence (the same "verify, don't trust" stance as
  verdicts). Forged/uncheckable claims don't reach quorum.
- **FL-C2 — verdicts are the first instance, not a parallel system.** Reuse the
  signed-verdict + quorum aggregation; an attestation verdict is `predicate =
  measured-state-matches-reference`. The ledger is the audit/timeline chain, so
  facts get the same hash-chained, replayable provenance.
- **FL-C3 — facts expire and are re-witnessed (MB-bound).** A signed fact carries a
  beacon round; "patched" is only current as of that round, so compliance state is
  freshness-bounded, not a stale one-time stamp.

**Phases**

| Phase | Scope |
|-------|-------|
| FL1 | ✅ done. `citadel-facts`: `Assertion {subject,predicate,claim,beacon_round,evidence}` + `FactChecker` (mock `SbomHashChecker`, `PatchedChecker`); `FactVote::cast` (independent check → signed ballot) + `FactAttestation::{approvals,witnessed_true}` (quorum of eligible checkers, mirrors ReleaseAuthorization). Tests: checkers verify evidence; a quorum of checking witnesses attests a fact while a false claim gets zero approvals; forged/duplicate/outsider votes do not count. |
| FL2 | ✅ done. `FactMessage` (Assert/Vote) + `FACT_TOPIC` gossip serde; `FactLedger` records attestations iff witnessed-true and answers queries — `is_witnessed(subject, predicate)` and `fleet_satisfies(predicate, subjects)` ("is the whole fleet patched for CVE-X?"). Tests: message round-trips; the ledger records witnessed facts + answers the fleet-unanimity query; a false attestation is not recorded. Durable audit-chain append + control-plane API are FL3. |
| FL3 | 🔨 in-tree slice done: `fact_selector` + `FactLedger::selectors_for` (the `citadel:fact-<predicate>` policy selector, mirrors `citadel:tpm-spec`) + `fleet_rollup`/`FleetRollup` (fleet-wide witnessed counts + unanimity). The control-plane API wiring + dashboard panel are deployment. |

---

## CA — Mesh-operated signing service / threshold CA

The threshold crypto (MSS6b) exists as a library; as a *service* it's a strong
primitive: a cluster key **no node holds**, that signs releases/configs/certs only
under live quorum **and** a healthy trust state. "The cluster has a root authority
that can only act by consensus, and won't act while compromised."

**Unlocks:** trust-gated release/firmware/config signing; a cluster CA whose
issuance halts automatically during an incident; a signing authority with no
single point of key compromise.

**Design calls**

- **CA-C1 — sign only under live quorum + trust.** A signing request runs the
  release protocol (CAP/MSS): witnesses vote on the *requester's* trust **and** the
  cluster's health, then the FROST holders co-sign. No standing signing oracle —
  every signature is a fresh quorum decision.
- **CA-C2 — DKG, not a dealer (no node ever holds the key).** Use the FROST **DKG**
  path (MSS6b hardening) so the CA key is never formed anywhere — the literal
  realization of "no single point of trust" for the cluster authority.
- **CA-C3 — what it signs is itself a fact (FL).** The artifact being signed is an
  assertion the mesh witnessed (e.g. "this release matches its reproduced build"),
  so the signature attests *a checked fact*, not just bytes.

**Phases**

| Phase | Scope |
|-------|-------|
| CA1 | ✅ done. `citadel-ca`: `ca_keygen` (DKG — no node holds the key), `signing_secret_id`, `ClusterHealth` (the OBS2 trust-score gate), `sign_artifact` (signs iff quorum-authorized AND healthy; refuses otherwise) → `SignedArtifact::verify`. Tests: signs under quorum+health and verifies; unhealthy / below-quorum / wrong-artifact refused; live harness — a signing request is authorized for a Trusted requester, denied for a compromised one. |
| CA2 | ✅ done. `SigningRequest` (+ `CA_TOPIC` gossip serde, secret-class id) for the request/approve/sign flow; `release_artifact`/`cert_artifact` issuance helpers; `CaStatus`/`ca_status` + `service_sign` — the CA halts (refuses) while the cluster is unhealthy and signs when Available + quorum-authorized. Tests: signs when Available + verifies, halts during an incident; issuance helpers + request round-trip. |
| CA3 | 🔨 in-tree slice done: `rotate` (DKG a fresh epoch key; the outgoing holders threshold-sign a `RotationAttestation` binding it) + verify — key continuity across epochs, a verifier trusting the old key follows to the new; a successor cannot self-authorize. Holder pinning across nodes + release-pipeline integration are deployment. |

---

## TW — Distributed tripwires / honeytokens

Seed decoy secrets/credentials/files across the fleet; any access gossips an alert
and trips the quarantine machinery. Cheap, high-signal deception that closes the
detection→containment loop.

**Unlocks:** a fleet-wide intrusion tripwire where one touched honeytoken triggers
*witnessed* quarantine — turning the mesh from "verify good state" into "actively
detect compromise."

**Design calls**

- **TW-C1 — a tripwire trip is signed evidence, not a bare alert.** The node that
  observes the access emits a signed `TripEvent` (what was touched, when, by
  whom); witnesses corroborate where possible. False/forged trips don't enact.
- **TW-C2 — trips feed the existing quarantine, gated by class.** A high-confidence
  trip (e.g. a sealed honeytoken decrypted) proposes quarantine via the M2 flow; a
  low-confidence trip degrades trust / raises a finding. Reuse propose→vote→enact.
- **TW-C3 — decoys are placed, never gossiped in clear.** Honeytoken *contents* are
  MSS-sealed; only their *identifiers* + access-detection ride gossip, so the trap
  itself isn't leaked by the mesh.

**Phases**

| Phase | Scope |
|-------|-------|
| TW1 | ✅ done. `citadel-tripwire`: `TripClass` (SealedDecoy/Credential=High, DecoyFile/Canary=Low) → `TripAction` (ProposeQuarantine vs RaiseFinding); `Tripwire` (stable id, never contents — TW-C3); signed `TripEvent` (observer/subject/what/when, TW-C1). Tests: class→action mapping; a signed trip verifies while tamper + forged-key fail; ids stable + distinct. |
| TW2 | ✅ done. `TRIP_TOPIC` + `TripEvent` gossip serde; `triage` verifies drained trips against their observers and turns high-confidence attributable ones into `Containment` recommendations (scope per class); `quarantine_scope`. Live harness: a sealed-decoy trip gossips over AppRelay → a witness triages → proposes quarantine via the M2 flow → the compromised node is contained mesh-wide. |
| TW3 | 🔨 in-tree slice done: `Detector` trait + `SoftwareDetector` (arm tripwires; an access to an armed decoy emits a signed, attributable trip). Real hooks (eBPF/file/credential-store, MSS-sealed-decoy unsealing) are deployment. |

---

## FED — Cross-mesh federation / trust bridging

Bridge trust between meshes/sites under explicit, attenuating policy (the "mesh
trust bundles" sketched in the observability doc) — the SPIFFE-federation analog
for the trust fabric itself.

**Unlocks:** multi-cluster / multi-org trust sharing — a workload in mesh A can be
admitted by mesh B's policy under a bounded, revocable bridge.

**Design calls**

- **FED-C1 — a bridge translates, it doesn't merge.** Mesh B accepts a *bundle* of
  mesh A's signed trust facts (FL) under a policy that maps/limits them (e.g. A's
  `Trusted` ⇒ B's `Suspect` unless co-attested); no mesh dissolves into another.
- **FED-C2 — bridges are themselves capabilities (CAP).** The authority to bridge
  is a mesh-issued, lease-bound, attenuable capability — so a federation link is
  continuously earned and revocable, like everything else.
- **FED-C3 — federate the spec/tier too.** Cross-mesh policy can require the device
  tier (`citadel:tpm-spec=2.0`, T3) and freshness (MB), so a weaker remote mesh is
  bounded in what it can vouch for.

**Phases**

| Phase | Scope |
|-------|-------|
| FED1 | ✅ done. `citadel-federation`: signed `TrustBundle` (origin + trust claims + tier + beacon round) + `ImportPolicy` (trusted issuer, ceiling trust, required tier, freshness) + `import` (verify → translate → cap; downgrade-only, FED-C1). Tests: bundle signs/verifies (tamper fails); import caps remote Trusted to the ceiling while a remote Suspicious stays Suspicious; drops stale/wrong-tier claims and rejects untrusted issuers. |
| FED2 | ✅ done. `import_gated` requires a valid bridge **capability** (`citadel-caps`): the operator must hold a `federate:<origin>` token (verified by a `Pep`) before a bundle is imported — so a federation link is continuously earned + revocable (FED-C2). `TrustBundle::{to_bytes,from_bytes}` for transport. Tests: a valid bridge cap imports; a wrong-origin or expired cap is unauthorized. SPIFFE-federation alignment is FED3 (deployment). |
| FED3 | Multi-mesh deployment + observability federation (the OBS5 gateway tier). (Needs multiple live meshes.) |

---

## Notes on sequencing

- **MB and CAP are mutually reinforcing** and cheap: MB gives CAP its freshness
  anchor, and CAP gives MB its first real consumer (capability TTLs by round). Both
  reuse machinery that's already live (FROST, the release protocol). Start here.
- **FL is the broadest new surface** (compliance/supply-chain), and **CA**
  productizes the threshold crypto — both are strong product stories and largely
  in-tree-testable (the live-deploy parts are clearly bounded).
- **TW and FED** are valuable but more specialized / deployment-heavy; they layer
  cleanly once MB/CAP/FL exist (TW reuses quarantine; FED reuses FL + CAP).

As with the prior roadmaps, each primitive's in-tree core (protocol + crypto +
tests) is the deliverable; the live-deployment portions (multi-node services,
detection hooks, multi-mesh) are scoped honestly and gated on real infrastructure.
