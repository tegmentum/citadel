# Design: Measured Merkle Anchoring, Measurement, and Sealing

Status: Draft
Audience: citadel maintainers
Related: `crates/tpm-core/src/backend/traits.rs`, `secure-log` (sibling repo), `src/commands/{pcr,secret,attest,policy,identity,audit}.rs`

## 1. Summary

Today citadel is a *consumer* of TPM measurements: it reads PCRs, takes quotes,
seals secrets, and keeps a tamper-evident audit log. It does not itself measure
anything into the TPM, and the `TpmBackend` trait has no `pcr_extend`.

This document proposes three additive capabilities:

1. **Measurement** — let citadel record a measurement of an artifact (binary,
   config, workload) and, where useful, extend it into a PCR.
2. **Merkle anchoring** — represent the open-ended set of application
   measurements as leaves of a Merkle tree, anchored to hardware by a TPM
   **key that signs the tree root** (a checkpoint). This is the "break the
   linear PCR chain at the kernel and branch into a tree" pattern.
3. **Sealing to measured state** — bind secrets and the anchoring key's own use
   to a measured state, so only a correctly-measured citadel can sign roots or
   unseal secrets.

The guiding model (per design discussion):

> We add **keys** and **tree hashes**. A key just **signs a particular hash** —
> the Merkle root.

So the linear PCR chain stays small and is used only for the static TCB
(firmware → boot → kernel → the measured agent). Above that, measurements live
in a software Merkle tree whose root is signed by a TPM key. The TPM provides
the *root of trust* (a key, gated on measured state); the tree provides scalable,
order-independent, inclusion-provable structure.

Most of the tree+signature machinery already exists in `secure-log`
(Merkle-sealed segments, `CheckpointSigner`, inclusion proofs, anti-rollback
head file). The new work is: a PCR-extend primitive, a measurement service that
feeds a dedicated measurement stream, real PCR-policy sealing, and binding the
anchoring key to measured state.

## 2. Background

- **PCR extend** is a linear hash chain: `PCR = H(PCR ‖ measurement)`. It is
  append-only and order-dependent. Great for a small ordered TCB; unusable as a
  place to fold the entire open-ended application universe (the value becomes
  unpredictable, breaking sealing/attestation — see `service/fragility.rs`,
  which already flags "IMA measurements (high churn under normal use)").
- **Merkle tree** over a *set* of measurements yields a root that is a function
  of the set (order-independent if sorted), supports `O(log n)` inclusion
  proofs, and allows partial verification without shipping the whole list.
- **Anchor** = a TPM key signs the Merkle root. The signature ties the
  software-maintained tree to hardware. Optionally the root is *also* extended
  into one dedicated PCR so secrets can be sealed against "the attested set."

This is the shape of transparency logs (CT, Rekor) and is exactly what
`secure-log` already implements.

## 3. Trust model — should citadel be "the agent at the root"?

**Recommendation: No — citadel is a *delegated, measured* agent, not the root of
trust.**

The root of trust must be the hardware Root of Trust for Measurement plus the
measured boot chain (firmware → bootloader → kernel → the agent binary). citadel
is a large userspace Rust platform; it cannot be its own root, and putting a
large binary in the trusted measuring path maximizes attack surface.

citadel *should* be the **application-layer measurement agent and log
authority** — the thing that maintains the Merkle tree and signs roots — but its
authority must be **derived, not assumed**:

- citadel's own binary is measured by the layer below it (kernel/IMA, or a
  measured launcher) into a TCB PCR.
- The TPM **anchoring key** citadel uses to sign Merkle roots has its
  authorization **policy-bound to that measured state** (PCR policy). A tampered
  or unmeasured citadel cannot use the key, so it cannot forge valid
  checkpoints.
- Therefore "citadel as agent at the root of the *application branch*" is fine;
  "citadel as the *root of trust*" is not. The boundary is: hardware+boot+kernel
  vouch for citadel; citadel vouches for applications.

Corollary — keep citadel's trusted footprint minimal:

- Prefer to consume raw measurements from a smaller, lower component where
  possible (e.g. IMA) and have citadel *organize and anchor* them into the
  Merkle log, rather than citadel doing all the hashing in the trusted path.
- The only citadel code that must be in the TCB is the path that (a) reads
  measurements, (b) builds the tree, and (c) drives the TPM signature. Keep that
  surface small and auditable.

Two anchoring mechanisms, which compose:

| Mechanism | What it gives | Cost |
|-----------|---------------|------|
| **(A) Key signs the Merkle root** (primary) | Order-independent set attestation, inclusion proofs, partial verification. Already built in `secure-log`. | Key must be bound to measured state to be trustworthy. |
| **(B) Extend the root into one PCR** (optional) | Lets secrets be *sealed* to "the attested application set" via standard PCR policy. | One extend per checkpoint; PCR value changes each checkpoint (manage via policy on a dedicated PCR). |

We implement (A) first (it is mostly done) and (B) as a follow-on for
sealing-to-attested-set use cases.

## 4. Architecture

### 4.1 Measurement primitive (PCR extend)

Add to `TpmBackend` (`crates/tpm-core/src/backend/traits.rs`):

```rust
/// Extend `value` into PCR `index` of `bank`: PCR = H(PCR ‖ value).
fn pcr_extend(&self, bank: &str, index: u32, value: &[u8]) -> anyhow::Result<()>;
```

Implementations:

- **mock** (`backend/mock.rs`): maintain an in-memory PCR map, fold deterministically.
- **vtpm** (`src/vtpm_bridge.rs`): add `build_pcr_extend_cmd()` emitting
  `TPM2_CC_PCR_Extend` (mirrors the existing `build_pcr_read_cmd`). Note the
  vtpm-wasm engine also exposes `hash_start/hash_data/hash_end` (TIS extend of
  PCR 17 at locality 4) — use the raw `TPM2_CC_PCR_Extend` path for parity with
  hardware rather than the TIS hash interface.
- **hardware** (`backend/hardware.rs`): `tss-esapi` `pcr_extend`.

New command surface:

- `tpm pcr extend <bank> <index> --input <file>|--value <hex>` — raw extend.
- `tpm measure <artifact> [--stream <name>] [--pcr <bank:index>]` — hash an
  artifact, record it as a measurement (§4.2), and optionally also extend a PCR.

### 4.2 Merkle-anchored measurement log (reuse `secure-log`)

Use the existing `NativeSecureLog` with a dedicated stream, e.g. `measurement`
(tier `protected`). The mapping is direct:

| Concept | `secure-log` API (see `src/commands/audit.rs`) |
|---------|-----------------------------------------------|
| Measurement (leaf) | `log.append("measurement", "artifact.measure", sev, producer, payload)` |
| Tree root (checkpoint) | `log.close_segment("measurement") -> SegmentInfo { merkle_root, .. }` |
| Key signs the root | `log.sign_segment(&TpmCheckpointSigner, identity, segment_id)` |
| Prove "X was measured" | `log.inclusion_proof(seqno) -> InclusionProof`; `verify_inclusion_proof(&proof, root)` |
| Anti-rollback | `NativeSecureLog::with_head_file(..)` |

Measurement entry payload (CBOR via the existing `CborEncoder`) — proposed
fields:

```
{
  artifact_id:   string,   // logical name, e.g. "workload/foo@1.2.3"
  digest_alg:    string,   // "sha256"
  digest:        bytes,    // hash of the artifact
  kind:          string,   // "binary" | "config" | "container" | ...
  pcr:           u32?,     // PCR index if also extended (§4.1), else null
  recorded_by:   string,   // producer (citadel agent id)
  metadata:      map?,     // optional source/provenance
}
```

This reuses the entry hash-chain, Merkle segmenting, signing, and inclusion-proof
code unchanged. The "tree hashes" are the segment Merkle roots; the "keys"
are citadel identities used as `CheckpointSigner`.

### 4.3 Keys and tree hashes (the core model)

- **Tree hashes**: produced by `secure-log` segment sealing (`close_segment`).
- **Keys sign a particular hash**: `TpmCheckpointSigner`
  (`crates/tpm-core/src/secure_log_signer.rs`) already signs the checkpoint hash
  for a closed segment with a TPM-backed identity key, and verifies it. The
  "particular hash" is the segment checkpoint over the Merkle root.
- The signing identity is a normal `tpm identity` (usage `attestation`). Its
  backing key lives in the TPM; §4.4 binds the key's *use* to measured state.

No new cryptographic machinery is required for (A) — only configuration: a
dedicated measurement-signing identity and a convention for when segments close
(e.g. on a timer, on N measurements, or on demand before a quote).

### 4.4 Sealing to measured state

Two distinct uses of sealing:

1. **Seal the anchoring key to measured state.** The measurement-signing
   identity's TPM key should only be usable when the boot chain + citadel are in
   the expected measured state. Express this as a `Policy` with
   `PolicyRule::PcrMatch { bank, indices }` over the TCB PCRs and attach it to
   the identity (`Identity.policy_id`). This is what makes "citadel as agent"
   safe: a tampered citadel cannot sign roots.

2. **Seal user secrets to the attested set (optional, needs §4.1(B)).** With the
   Merkle root extended into a dedicated PCR, `tpm secret seal --policy
   <pcr-policy>` can bind a secret to "the system measured this exact set."

Gap to fix for real enforcement: today `secret.rs` passes `policy.id` (a UUID)
as the `policy_digest` to `backend.seal()`. That is a placeholder, not a real
TPM policy digest, so unseal is not actually PCR-gated. We need:

```rust
// new on TpmBackend (or a helper):
fn pcr_policy_digest(&self, bank: &str, indices: &[u32]) -> anyhow::Result<Vec<u8>>;
```

so a `PolicyRule::PcrMatch` compiles to the genuine `TPM2_PolicyPCR` digest,
which is what `seal()` binds to and what the TPM enforces at `unseal()`. This
makes the existing `policy create --pcr` path real end-to-end.

## 5. Interfaces and data-model changes (summary)

- `TpmBackend`: add `pcr_extend`, `pcr_policy_digest`. Implement in mock / vtpm /
  hardware.
- `src/vtpm_bridge.rs`: add `build_pcr_extend_cmd` (and policy-digest support).
- `secure-log`: no code change — add a `measurement` stream + entry schema
  convention.
- Policy: make `PolicyRule::PcrMatch` compile to a real TPM policy digest;
  enforce on seal/unseal. Allow attaching a policy to an `Identity` so its key
  use is PCR-gated.
- Commands: `tpm pcr extend`, `tpm measure`, `tpm measure verify <artifact>`
  (inclusion proof), `tpm secret seal --pcr`, and an `attest` extension that
  bundles the latest signed measurement checkpoint into a quote.
- Anti-rollback: reuse the secure-log head file; consider a TPM NV monotonic
  counter for the checkpoint sequence (defense against head-file rollback).

## 6. Phased implementation plan

**Phase 0 — PCR extend primitive.**
Add `pcr_extend` to the trait + mock/vtpm/hardware impls. `tpm pcr extend`
command. Unit tests on mock (fold correctness, order dependence) and a vtpm
smoke test (`extend` then `read` reflects the fold).

**Phase 1 — Real PCR-policy sealing.**
Add `pcr_policy_digest`; compile `PolicyRule::PcrMatch` to a real digest; wire
`secret seal/unseal` to bind/enforce it. Replace the UUID placeholder. Tests:
seal under current PCRs, unseal succeeds; after an extend, unseal fails.

**Phase 2 — Measurement log.**
`tpm measure` hashes an artifact and appends to the `measurement` stream;
`measure verify` produces/checks an inclusion proof. Reuse `audit segments
close` + `audit sign` (or add `measure checkpoint`) to seal+sign roots. Tests:
measure → close → sign → verify chain + inclusion proof round-trip.

**Phase 3 — Bind the anchoring key to measured state.**
Create the measurement-signing identity with a PCR policy over the TCB PCRs
(`identity init --policy`). Verify the key is unusable when PCRs differ (mock by
forcing a mismatch). Document the bootstrap (how citadel's own measurement gets
into a TCB PCR — IMA-appraisal or a measured launcher).

**Phase 4 — Attestation integration.**
Extend `attest quote` to include the latest signed measurement checkpoint
(root + signature + signer identity) alongside the PCR quote, so a remote
verifier checks: boot PCRs (quote) → citadel measured → checkpoint signature →
inclusion proof for the app of interest.

**Phase 5 — Optional root-in-PCR + hardening.**
Extend the Merkle root into a dedicated PCR (mechanism B) to enable
seal-to-attested-set. Add an NV monotonic counter for anti-rollback. Evaluate
delegating raw measurement to IMA with citadel as the anchoring/serving layer to
shrink the TCB.

## 7. Security considerations

- **Measurement ≠ enforcement.** This records what ran; it does not block a bad
  app. Pair with IMA-appraisal / signing / Secure Boot for enforcement.
- **Load-time, not runtime.** A measurement is taken at record time; it says
  nothing about later process behavior. Be explicit about this in attestation
  semantics.
- **TCB size.** citadel-as-agent puts citadel in the trusted path. Minimize the
  trusted code; prefer consuming IMA measurements over re-hashing in citadel.
- **Bootstrapping.** citadel's trust is *derived* from being measured. If
  citadel is not measured into a TCB PCR and its anchoring key is not PCR-bound,
  the whole scheme degrades to "an app signing hashes with a key" — no better
  than a software log. The PCR-bound key (Phase 3) is the linchpin.
- **Rollback.** The software tree needs monotonicity: anti-rollback head file +
  (ideally) a TPM NV monotonic counter so an attacker can't replay an old
  signed root.
- **TOCTOU.** Between "measure" and "launch/use" the artifact could change. For
  real assurance, measure the exact bytes that execute (e.g. at exec, or seal
  the artifact) rather than a file that can be swapped.
- **Policy-digest correctness.** Until Phase 1 lands, sealing is NOT genuinely
  PCR-gated (UUID placeholder). Do not advertise sealed-to-PCR guarantees before
  then.

## 8. Open questions

1. **Who hashes?** citadel measures artifacts directly, or delegates raw
   measurement to IMA and only anchors/serves? (TCB-size trade-off.)
2. **PCR strategy:** sign-only (no PCR), root-in-one-PCR, or per-domain PCRs?
3. **Checkpoint cadence:** when do measurement segments close (timer / count /
   pre-quote)?
4. **citadel self-measurement source:** IMA-appraisal signature vs a measured
   launcher vs recording `current_exe` (weakest).
5. **NV anti-rollback:** which NV index, and provisioning story across backends.
6. **Multi-tenant streams:** one measurement stream per machine, or per
   workload domain (tiers already supported by secure-log)?
