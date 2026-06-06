# Citadel: Authorized Measured-State Transitions

Document Version: 0.2
Status: Layered design. Layers 1–3 **built** (`reference.rs`): multi-value
appraisal, per-PCR policy class, and signed manifests with artifact-identity
provenance + revocation. Layer 4 (boot profiles, quorum promotion, event-log
semantic validation) planned.
Project: Citadel
Audience: Architecture, Security, Platform, Runtime Engineers
Related: `distributed-attestation-mesh.md`, `distributed-log-shipping-lthash.md`,
`mma-upgrade.md`, `measured-merkle-anchoring.md`

> Companion to the [attestation mesh](distributed-attestation-mesh.md). The mesh
> decides trust from measured state matched against a golden reference; this doc
> covers how that golden **changes over time** — kernel, firmware, Secure Boot
> keys, bootloader, initrd, or Citadel's own agent hash — without a legitimate
> upgrade being mistaken for tampering, and without a tampered node being able
> to pass off its state as an upgrade.

## 0. The right abstraction: measured boot as *evidence*, not equality

The single most important shift this document makes: stop treating a TPM quote
as "this machine must equal this exact PCR vector" and start treating it as
"this machine followed an **accepted boot-state lineage**." An exact-hash
allowlist is bad for operations — every kernel / initramfs / firmware change
mints a new "unknown" state. A boot-state *policy* accepts a measured path if
its ingredients are valid.

Three roles, kept separate:

```
TPM quote   → proves the INTEGRITY of the measurement (it really is this PCR set)
event log   → EXPLAINS the measurement (which artifacts produced those PCRs)
policy      → DECIDES whether the explained measurement is acceptable
```

The target data model is therefore **not** `node_id → expected_pcrs`. It is:

```
node_id            → assigned_boot_profile
boot_profile       → semantic acceptance policy
observed quote     → reconstructed event chain      (replay(event_log) == quoted_PCRs)
event_chain + quote + signed manifest → accept | retire | reject | quarantine
```

This is delivered in **layers**, cheap-and-immediate first:

* **Layer 1 — value tier (built).** Multi-valued, validity-windowed accepted
  references (§§2–9). Graceful rollouts; still hash-enumerated.
* **Layer 2 — per-PCR policy class (§10.1).** Treat PCRs by *meaning* (strict /
  semantic / volatile) so volatile/semantic indices stop causing spurious
  failures. No event log required.
* **Layer 3 — signed manifests + artifact identity (§10.2).** Acceptance from
  *provenance* (signed by a trusted publisher, approved channel, version window,
  not revoked) rather than enumeration. The manifest is the authorization.
* **Layer 4 — boot profiles, quorum promotion, event-log semantic validation
  (§§10.3–10.4).** Named profiles a node *instantiates*; new states promoted
  through fleet quorum; full event-log replay + per-artifact policy.

Layers 1–3 operate on the quote alone. Layer 4's semantic validation is gated
on ingesting the **TCG event log** — Citadel does not carry it today (the §5/§6
gap in `distributed-log-shipping-lthash.md`), so until then the *semantic* PCR
class (§10.1) is value-unchecked, not magically validated.

## 1. Problem

A node earns trust by quoting its PCRs and having a verifier match them against
a golden `ReferenceMeasurements` by **exact equality** (`attest.rs` `verify`,
PCR loop). Any change to a measured component moves those PCRs, so a legitimate
upgrade is, byte-for-byte, indistinguishable from an attack:

* **kernel** → PCR 4 / 8 / 9 (kernel, cmdline, initrd)
* **firmware / option ROMs** → PCR 0 / 2 / 3
* **Secure Boot keys / db / dbx** → PCR 7
* **bootloader** → PCR 4
* **Citadel agent binary** → PCR 14 (the MMA self-measurement, see `mma-upgrade.md`)

Today the appraisal path has three gaps:

1. **Single golden, exact match** — a verifier holds one accepted value per PCR;
   it cannot accept "old *or* new" during a rollout.
2. **No overlap window** — a mixed fleet (some upgraded, some not) cannot all
   pass against one golden, so a rolling upgrade requires an atomic fleet flip.
3. **No authorization on reference updates** — `set_peer_reference` /
   `current_reference` let a reference be installed or self-captured with no
   signed authority, so there is no safe way to *distribute* a new golden.

What is **already handled** and out of scope here:

* **Reboot liveness** — a node that reboots for the upgrade goes
  `Alive→Suspect→Faulty` and auto-refutes via incarnation on return (`node.rs`).
* **Evidence log across reboot** — `boot_id` increments; old sealed windows stay
  valid durable evidence and the new boot is a fresh sequence namespace, so
  equivocation detection does not false-positive (`logship.rs`).
* **Local signing key** — the TPM-bound MMA key surviving a TCB change is solved
  by PolicyAuthorize and the upgrade ceremony (`mma-upgrade.md`, DONE). This doc
  is the **mesh appraisal** counterpart and is designed to share that ceremony.

## 2. Layer 1 — value tier: accepted references, two shapes at once (built)

> **Status: built** (`reference.rs`, wired through `attest.rs`/`node.rs`;
> tests `reference_transition.rs`). §§2–9 describe this layer.

A verifier no longer holds one golden; it holds a set of **accepted reference
sources**, and a quote is accepted if every selected PCR index is *explained* by
an active source. Two source shapes coexist (decision 1 = **both**):

* **Standalone per-index entry** — "PCR `i` may be digest `d`." Independent
  components (firmware, Secure Boot, kernel) each carry their own set of
  accepted digests, so they upgrade independently with no combinatorial blow-up.
* **Coupled profile** — "this *set* of `(index, digest)` pairs is accepted only
  together." For components that must move as a unit (e.g. kernel + cmdline +
  initrd), or for high-assurance deployments that reject mix-and-match.

**Acceptance rule.** For the selected indices and the quoted digests, a quote is
`Accepted` iff every selected index is explained by either (a) an active
standalone entry for that exact `(index, digest)`, or (b) an active coupled
profile that the quote fully satisfies over the indices the profile covers.

`ReferenceMatchPolicy` (decision 1, configurable) tunes this:

* `Flexible` (default) — standalone entries and coupled profiles both count.
* `CoupledOnly` — standalone entries are ignored; every selected index must be
  explained by a fully-satisfied profile (no mix-and-match).

A verifier can therefore run pure per-index, pure coupled, or a blend (per-index
for independently-patched components, coupled for the kernel triple).

## 3. Validity windows (decision 4: configurable, both clocks)

Each entry/profile carries a `Validity` bounded by **either or both** of the
mesh's two notions of time, so a deployment uses whichever it has:

```
Validity {
    from_revision: Option<u64>,  until_revision: Option<u64>,   // policy generation
    from_tick:     Option<u64>,  until_tick:     Option<u64>,   // logical/wall time
}
```

Against the current `(tick, policy_revision)` an entry resolves to:

* **Pending** — before a `from_*` bound (staged ahead of a rollout).
* **Active** — within bounds (counts toward acceptance).
* **Retired** — past an `until_*` bound (see §4).

Revision bounds suit the logical-tick mesh and signed-policy generations;
wall-clock bounds suit true scheduled rollouts. Both set → both must hold.

## 4. Retired-but-matching behaviour (decision 2: configurable)

When a quote matches *only* a **retired** source (the node is on a
previously-good but now-withdrawn state — i.e. unpatched, not tampered), the
verdict is governed by `RetiredAction`:

* `Fail` — strict: retired == untrusted (forces patching hard).
* `Warn` — degraded but tolerated.
* `GraceThenFail { grace }` — `Warn` until `grace` past the retirement bound,
  then `Fail` (a patch deadline).

This is distinct from matching **nothing known**, which is always a hard fail.

New reason codes (replacing the blunt `PCR_MISMATCH` for this path):

* `REFERENCE_UNKNOWN` — quoted state matches no accepted source → likely tamper.
* `REFERENCE_RETIRED` — matches only a retired source → unpatched.

## 5. Authorization (decision 3: configurable authority)

A reference source is adopted only if it is signed by a **reference authority**.
This reuses the existing endorser/anchor machinery (`TrustAnchors`,
`Endorsement`/`EndorserCert` signing in `types.rs`):

* A node holds `reference_authorities: TrustAnchors`. By default this **is** the
  AK-endorsement anchor set (one authority for both surfaces); it can be set to
  a **separate** anchor set for separation of duties (decision 3, configurable).
* Production references come only from a signed `ReferenceUpdate` — a node
  **never** adopts a self-captured reference. `current_reference` /
  `from_pcr_values` remain bootstrap/test conveniences that seed `Always`-active
  standalone entries on a known-good founder.
* The reference values themselves are produced by the RVP replaying the approved
  build's TCG measured-boot event log; the authority signs the resulting digests.

## 6. Transition lifecycle (closes the rolling-upgrade gap)

| Phase | Authority action | Effect on `verify` |
|-------|------------------|--------------------|
| Stage | Sign + gossip `ReferenceUpdate` **adding** the new digests (optionally `Pending` until a future bound) | old + new both accepted |
| Roll  | operator reboots nodes into the new state, gradually | upgraded match new, others match old — none fail |
| Retire| Sign + gossip a **retirement** of the old digests | stragglers fail/warn per `RetiredAction` |

Retirement is the security lever that turns graceful upgrade into enforced
patching. The retirement sweep can be rate-limited, reusing the gradual-migration
pattern from the durable-evidence placement work.

## 7. Distribution

A signed `ReferenceUpdate` is gossiped as a new `GossipMessage` variant and
merged idempotently (union of entries/profiles, with retirements as an overlay),
so ordering and duplication are safe and late/partitioned joiners converge.
Optional anti-entropy: periodically advertise a digest of the accepted set (same
shape as the LtHash `DigestAdvertisement`) so a node that missed an update pulls
it. Each adopted update is recorded in the evidence chain
(`evidence.rs` `RecordType::ReferenceUpdate`) for audit.

## 8. Interaction with probation / quarantine

* A node matching any **active** source → `Pass` → stays `Trusted`. An
  *authorized* upgrade therefore needs **no** re-probation.
* A node matching only a **retired** source → per `RetiredAction`.
* A node matching **nothing** → `Fail` → `Suspicious` → quarantine candidate, as
  today. Remediation/rejoin returns it to probation, not straight to trusted.

## 9. Coordination with the local MMA ceremony

A single operator "measured-state transition" should emit **both**:

1. the PolicyAuthorize approval for the local TPM-bound signing key
   (`mma-upgrade.md`, existing), and
2. the mesh `ReferenceUpdate` for the same component + new digest (new),

so a firmware/kernel/agent upgrade is one ceremony covering both the node's
ability to *sign* and the mesh's willingness to *trust* the new state.

## 10. Policy tier: from value allowlist to evidence-based acceptance

Layer 1 still answers "is this hash in the set?". The policy tier moves the
decision onto *meaning and provenance*. The pieces, cheapest first.

### 10.1 Per-PCR policy class (Layer 2 — in progress)

Not all PCRs deserve the same treatment. Each index carries a `PcrClass`:

* **`Strict`** — exact value-tier match (Layer 1). For platform/security-policy
  identity: firmware trust anchors, Secure Boot state, measured-boot-enabled,
  TPM/startup locality.
* **`Semantic`** — *not* value-matched; reserved for event-log policy (§10.4).
  For the volatile-but-meaningful components: bootloader, kernel, initramfs,
  kernel command line.
* **`Volatile`** — ignored entirely. Runtime config, device ordering, ephemeral
  boot variables.

A verifier keeps a per-index class map with a default of `Strict` (preserving
today's behaviour). The immediate operational win needs **no event log**:
reclassify churny indices out of `Strict` and they stop minting "unknown"
states. **Honest caveat:** until Layer 4 lands, a `Semantic` index is
*value-unchecked* — moving the kernel PCR to `Semantic` before the event-log
engine exists means the kernel is not appraised, only its integrity proven by
the quote. Use knowingly.

### 10.2 Signed manifests + signed artifact identity (Layer 3 — built)

> **Status: built** (`reference.rs`: `ReferenceManifest`, `ArtifactIdentity`,
> `FleetArtifactPolicy`; `node.rs`/`harness.rs` wiring; tests
> `reference_transition.rs`). A signed manifest gossips fleet-wide and is
> adopted only if its issuer chains to a trusted reference authority; entries
> carry artifact provenance gated by per-component channel / version-baseline /
> denylist policy, re-checked each appraisal so **revocation distrusts a
> running node** (`REFERENCE_DENIED`). Richer predicates (publisher key id,
> boot-param policy) layer on the same structure.

Acceptance from provenance, not enumeration. When the update system rolls a
kernel it emits a signed **manifest**:

```yaml
update:
  profile: ubuntu-24.04-prod-generic
  kernel_hash: ...        initramfs_hash: ...     grub_hash: ...
  package_versions: ...   build_id: ...
  valid_from: ...         valid_until: ...        signed_by: fleet-update-key
```

Citadel accepts a new measurement because it matches an approved, signed,
in-window, non-revoked **transition manifest** — controlled looseness without
blind trust. The policy for an artifact becomes, e.g. for the kernel:

```
accept kernel if: signature chains to a trusted publisher key
                  AND package/version in an approved channel
                  AND version >= security baseline AND not in denylist
                  AND boot params satisfy fleet policy
```

This is the Layer-1 signed `ReferenceUpdate` (§5) **generalised**: the manifest
*is* the authorization artifact, and the AK-endorsement chain-to-anchor
machinery (`TrustAnchors`, `EndorserCert`) is reused for publisher/manifest
signing. The hash is *evidence*, not the policy.

### 10.3 Boot profiles + fleet quorum promotion (Layer 4)

Named, versioned profiles a node **instantiates** rather than equals:

```yaml
profile: ubuntu-24.04-prod-generic
allowed:
  firmware: vendor-approved      secure_boot: enabled
  shim: signed-by Microsoft/Canonical   grub: signed-by Canonical
  kernel: { package: linux-image-generic, channel: prod-approved, min_version: 6.8.0-xx }
  initramfs: { generated-by: approved-pipeline }
  cmdline: { require: [lockdown=integrity], deny: [init=/bin/sh, selinux=0] }
```

Mapping: `node_id → assigned_boot_profile`. A new boot state is promoted through
the mesh, not declared by a central verifier:

```
unknown → observed → staged → quorum-accepted → fleet-accepted
```

A canary boots the new state and submits quote + event log + manifest; peers
**independently** validate signatures, provenance, and profile constraints; on
quorum the state becomes accepted for that profile. This reuses the mesh's
witness/enrollment quorum and the §3 `Pending→Active` staging.

### 10.4 Event-log semantic validation (Layer 4, gated)

The deep piece, and the dependency everything semantic rests on. Validate the
**event log that produced the PCRs**, not just the PCR values:

```
1. ingest the TCG event log (§5/§6 of distributed-log-shipping-lthash.md)
2. replay(event_log) == quoted_PCRs        ← integrity: the log explains the quote
3. apply per-artifact policy to the events  ← decision: signed-by, channel, version, cmdline
```

The value tier doesn't vanish — it *moves*: "match the PCR vector" becomes "the
log replays to the quoted vector," and policy shifts onto the individual events.
This aligns with the IETF RATS appraisal-policy-for-evidence model. **Blocked
on** event-log ingestion, which Citadel does not have today.

### 10.5 Where the layers meet

```
quote ──(integrity)──► PCR vector
                          │  Strict indices  ─► Layer 1 value match
                          │  Semantic indices ─► Layer 4 event-log policy (else value-unchecked)
                          │  Volatile indices ─► ignored
event log ──(replay == quote)──► events ─► Layer 3 manifest / artifact policy
                                              ▼
                              assigned profile (Layer 4) ─► accept | retire | reject | quarantine
```

## 11. Phased delivery

* **Layer 1 — multi-value appraisal engine. ✅ Built.** `reference.rs`
  (`ReferenceEntry`/`ReferenceProfile`/`AcceptedReferences`/`Validity`/
  `RetiredAction`/`ReferenceMatchPolicy`/`appraise`), wired through `attest.rs`
  `verify` with `REFERENCE_UNKNOWN`/`REFERENCE_RETIRED`; config `reference_match`
  / `retired_action`; tests `reference_transition.rs`.
* **Layer 2 — per-PCR policy class (§10.1). ◑ In progress.** `PcrClass` on
  `AcceptedReferences`; `appraise` consults it; node/harness setters. No event
  log required.
* **Layer 3 — signed manifests + artifact identity (§10.2). ✅ Built.**
  `ReferenceManifest` (issuer anchored directly or via publisher cert chain),
  `reference_authorities` anchors (decision 3), idempotent gossiped adoption;
  `ArtifactIdentity` + `FleetArtifactPolicy` (channel / version-baseline /
  denylist), re-checked each appraisal so revocation takes effect on running
  nodes (`REFERENCE_DENIED`). Adopted manifests are recorded in a hash-chained
  audit (`RecordType::ReferenceUpdate`) and re-advertised for anti-entropy
  (`ReferenceDigest` → `ReferenceManifestRequest`) so a node that missed a
  gossiped manifest pulls it and converges. **Complete.**
* **Layer 4 — boot profiles, quorum promotion, event-log semantic validation
  (§§10.3–10.4).** `node_id → profile`; promotion lifecycle over mesh quorum;
  TCG event-log ingestion + replay + per-artifact policy. Unify with the MMA
  PolicyAuthorize ceremony (§9). Largest; gated on event-log work.

## 12. Open items

* Coupled-profile identity: hash of its `(index, digest)` set as `profile_id`.
* Whether `GraceThenFail` counts grace in ticks, revisions, or both (likely both,
  mirroring `Validity`).
* Anti-entropy frequency and whether reference state piggybacks on existing
  gossip or rides its own interval.
* `Semantic` class before Layer 4: value-unchecked (current plan) vs. an
  interim `Warn` so the gap is visible — leaning value-unchecked to avoid
  perpetual-warn noise, documented loudly.
* Revocation source for artifact identity (denylist distribution) — likely a
  signed list rides the same manifest channel.
