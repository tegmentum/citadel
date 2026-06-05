# Plan: vTPM NV anti-rollback counter + TPM-enforced policy-session signing

Status: Draft / not started
Scope: the two remaining non-hardware deferred items from the
measured-Merkle-anchoring work. Both are raw TPM2 protocol work in
`src/vtpm_bridge.rs` (the vTPM is software/libtpms, so both are testable
here without physical hardware). The `tpm-hw` (tss-esapi) equivalents are
separate and need real hardware.

---

## Item 1 — vTPM NV monotonic counter (`nv_increment`)

> **Status: primitive DONE** (`feat(vtpm): implement TPM2 NV monotonic
> counter ...`). The attribute-bit fix below resolved it; `nv_increment`
> works on the vTPM and persists across invocations (1,2,3,… via the
> state file). Tests cover in-process monotonicity and cross-instance
> persistence. **Remaining:** bind the counter into the signed
> checkpoint (secure-log change, below), and the `tpm-hw` (tss-esapi)
> equivalent (needs hardware).

### Goal

Implement `TpmBackend::nv_increment` for `VtpmBackend` using a real
counter-type NV index, so `tpm measure anchor-counter` returns a
hardware-monotonic value that **persists across invocations** (NV is part
of the permanent state we already snapshot). This is the basis for
anti-rollback.

### What's known — the failed attempt and its likely root cause

A first attempt (reverted) tried `TPM2_NV_DefineSpace` (counter) +
`TPM2_NV_Increment` + `TPM2_NV_Read` and hit:

- owner-auth path → `TPM_RC_NV_AUTHORIZATION (0x149)`
- index self-auth path → `TPM_RC_AUTH_UNAVAILABLE (0x12f)`

**Root cause found while writing this plan: the `TPMA_NV` attribute bits
were mis-encoded.** Correct bit positions (TPM 2.0 Part 2, TPMA_NV):

| Attribute | Bit | Value |
|-----------|-----|-------|
| `OWNERWRITE` | 1 | `0x0000_0002` |
| `AUTHWRITE`  | 2 | `0x0000_0004` |
| `TPM_NT = COUNTER` | 4–7 | `0x0000_0010` |
| `OWNERREAD` | 17 | `0x0002_0000` |
| `AUTHREAD`  | 18 | `0x0004_0000` |
| `NO_DA`     | 25 | `0x0200_0000` |

The attempt used `0x0004_0000` for `OWNERREAD` (that's actually
`AUTHREAD`) and `0x0002_0000` for `AUTHREAD` (that's actually
`OWNERREAD`) — i.e. the read attributes were swapped, so the defined
index didn't grant the read/write combo the auth path assumed. Fixing
the constants alone may resolve both errors.

### TPM2 protocol design

Use a single, consistent auth model. Recommended: **owner hierarchy**.

- **Define** (`TPM2_CC_NV_DefineSpace = 0x0000012A`): `authHandle =
  TPM_RH_OWNER`, empty PW auth; `TPMS_NV_PUBLIC` with
  `attributes = OWNERWRITE | OWNERREAD | COUNTER | NO_DA`
  (`0x0002_0012` with the corrected bits), `nameAlg = SHA256`,
  `dataSize = 8`, empty `authPolicy`. Idempotent: tolerate
  `TPM_RC_NV_DEFINED (0x14C)`.
- **Increment** (`TPM2_CC_NV_Increment = 0x00000134`): handles
  `authHandle = TPM_RH_OWNER`, `nvIndex = index`; empty PW auth. First
  increment initializes the counter to a TPM-chosen value `>=` the reset
  count (monotonic across redefine).
- **Read** (`TPM2_CC_NV_Read = 0x0000014E`): handles `TPM_RH_OWNER`,
  `nvIndex`; params `size = 8, offset = 0`; response is a
  `TPM2B_MAX_NV_BUFFER` (8-byte big-endian counter).

Default index: `0x0180_0001` (the existing `ANCHOR_COUNTER_NV_INDEX` in
`src/commands/measure.rs`).

### Implementation steps

1. Add command codes + the **corrected** `TPMA_NV_*` constants to
   `src/vtpm_bridge.rs`.
2. Add `pw_auth_area()` helper and `build_nv_define_counter_cmd`,
   `build_nv_increment_cmd`, `build_nv_read_cmd`.
3. Override `VtpmBackend::nv_increment`: define (tolerate `NV_DEFINED`)
   → increment → read → parse 8-byte value.
4. **Diagnostic ladder** (so the next auth error is debuggable): after
   define, issue `TPM2_NV_ReadPublic (0x00000169)` and log the actual
   attributes/dataSize the TPM stored — confirms the define landed as
   intended before increment/read.

### Testing (real vTPM, gated on `TPM_VTPM_COMPONENT`)

- In-process unit test in `vtpm_bridge.rs`: `nv_increment` twice returns
  strictly increasing values; a second index counts independently.
- Cross-instance test: increment in backend instance 1 (persist on
  drop), reopen instance 2 from the same state file, increment again →
  value continues (NV survived via permanent state). This is the
  anti-rollback property and is the real payoff of persistence.
- CLI: `tpm measure anchor-counter --backend vtpm` across 3 separate
  invocations against one store shows a monotonically increasing value.

### Follow-on — bind the counter into the checkpoint (anti-rollback)

Once the counter works, wire it into signing so a verifier can detect
rollback:

- At `measure sign` time, read the current counter and include it as a
  field the **signature covers**. This requires the checkpoint message
  to include the counter — i.e. a change in the **`secure-log`** crate
  (the checkpoint hash is computed there). Options:
  - (a) Add an optional "external counter" field to the segment
    metadata that `sign_segment` folds into the checkpoint hash.
  - (b) Keep the counter in a citadel-side sidecar signed alongside the
    checkpoint, and have `attest verify` cross-check it.
- Verification (`attest verify` / `audit verify`) reads the live NV
  counter and rejects a checkpoint whose counter is below it.

This follow-on is cross-repo (secure-log) and is the larger half; the
NV primitive (above) is the prerequisite and is self-contained.

### Risks

- Further component-specific NV-auth quirks beyond the attribute fix —
  the `NV_ReadPublic` diagnostic makes these quick to localize.
- Counter value is not guaranteed to start at 1 (TPM-chosen); treat it
  as opaque-monotonic, compare with `>=`.

### Effort: ~half a day for the primitive + tests; the secure-log
checkpoint-binding follow-on is a separate ~1–2 day cross-repo change.

---

## Item 2 — TPM-enforced policy-session signing

> **Status: DONE** (`feat(vtpm): TPM-enforced policy-session signing ...`,
> `feat(mock): software policy-signing ...`, `feat(identity): wire ...`).
> Validated end-to-end on the real vTPM: an identity created with
> `tpm identity init --pcr-bind <indices>` signs checkpoints only while
> the bound PCRs match; after they change the **TPM** refuses with
> `TPM_RC_POLICY_FAIL (0x099d)`. The marshalling worked first try, which
> also confirmed `backend::pcr_policy_digest` matches the TPM's PolicyPCR
> digest exactly. **Remaining (follow-on):** `PolicyAuthorize`
> upgradability so a legitimately-updated expected state can be
> re-authorized without rotating the key; and the `tpm-hw` (tss-esapi)
> equivalent (needs hardware).

### Goal

Replace (or back up) the citadel-side measured-state gate
(`measure sign --require-baseline`, a software PCR check in
`crates/tpm-core/src/secure_log_signer.rs`) with **TPM enforcement**: the
signing key is bound to an `authPolicy` such that the TPM itself refuses
to sign unless live PCRs match the expected state. A tampered/unmeasured
citadel then cannot produce a valid checkpoint even by skipping the
software check.

### Current state

- `create_key` (`src/vtpm_bridge.rs`) builds keys with `userWithAuth`
  (password auth), no `authPolicy`.
- `sign` loads the key under the SRK and signs under a **PW session**.
- The measured-state gate is entirely in `TpmCheckpointSigner`
  (software): read PCRs → compute PolicyPCR digest → compare to a saved
  baseline → refuse on mismatch.

### TPM2 protocol design

The standard "key usable only in a PCR state" pattern:

1. **Key creation with `authPolicy`** — when creating the
   measurement-signing identity's key, set
   `TPMT_PUBLIC.authPolicy = PolicyPCR-digest(baseline PCRs)` and clear
   `userWithAuth` (so the key requires policy, not password). The
   PolicyPCR digest is the same value `backend.pcr_policy_digest(...)`
   already computes (the citadel-side helper), so the expected-state
   math is shared.
2. **Sign under a policy session** —
   - `TPM2_StartAuthSession (0x00000176)` → a **policy** session
     (`sessionType = TPM_SE_POLICY = 0x01`), `TPM_ALG_SHA256`, null
     bind/salt, a fresh caller nonce.
   - `TPM2_PolicyPCR (0x0000017F)` on the session for the bound PCR
     selection — the TPM folds the **live** PCR values into the
     session's `policyDigest`.
   - `TPM2_Sign` with the session as the auth session for the key.
   - If live PCRs differ from the baseline, the session `policyDigest`
     ≠ the key's `authPolicy` → `TPM_RC_POLICY_FAIL` and the TPM refuses.
   - `TPM2_FlushContext` the session.

### Implementation steps

1. **Backend surface**: add an optional policy to key creation, e.g.
   `create_key_with_policy(alg, path, auth_policy: &[u8])`, and a
   `sign_with_policy(handle, data, pcr_bank, pcr_indices)` that runs the
   StartAuthSession + PolicyPCR + Sign sequence. Keep existing
   `create_key`/`sign` unchanged (password keys) so only the
   measurement-signing identity opts in.
2. **vTPM marshalling** (`src/vtpm_bridge.rs`): `build_start_auth_session_cmd`,
   `build_policy_pcr_cmd`, and a `build_sign_cmd` variant that uses the
   policy session handle in the auth area instead of `TPM_RS_PW`. Reuse
   `pw_auth_area`/session-area helpers.
3. **Identity creation**: `tpm identity init --pcr-policy <baseline>`
   (or reuse `--require-baseline` semantics) — at creation, compute the
   PolicyPCR digest from the named baseline and create the key bound to
   it. Record on the identity that it is policy-bound.
4. **Signer**: `TpmCheckpointSigner` detects a policy-bound identity and
   calls `sign_with_policy` (the TPM enforces); the existing software
   `--require-baseline` gate stays as defense-in-depth / for
   non-policy-bound keys and the mock backend.
5. **Mock backend**: implement `sign_with_policy` as the existing
   software gate (so tests run without the vTPM).

### Testing

- In-process vTPM test: create a policy-bound key at the current PCR
  state, sign (succeeds), `pcr_extend` a bound PCR, sign again →
  `TPM_RC_POLICY_FAIL` (the **TPM** refuses, not citadel).
- CLI cross-invocation on persistent vTPM: identity bound to a baseline
  signs while PCRs match, refused (by the TPM) after a measurement
  changes them — same observable behavior as today's software gate but
  now hardware-enforced.

### Risks / open questions

- **Protocol surface is larger** than NV (sessions, nonces, policy
  digest evolution). Budget for iterative debugging like the NV item;
  add an `NV_ReadPublic`-style diagnostic (`TPM2_PolicyGetDigest
  0x00000189`) to compare the session digest against the key's
  authPolicy when a sign is rejected.
- **Policy upgradability**: a key hard-bound to one PCR state can't sign
  after a *legitimate* update. The standard fix is `PolicyAuthorize`
  (bind to a signed policy authority so the expected state can be
  re-authorized without rotating the key). Recommend shipping the simple
  fixed-policy version first, then `PolicyAuthorize` as a follow-on.
- **Scope creep**: only the measurement-signing identity should be
  policy-bound; keep all other keys on the password path to avoid
  destabilizing unrelated signing.

### Effort: ~2–3 days (StartAuthSession/PolicyPCR/Sign marshalling +
identity wiring + tests). `PolicyAuthorize` upgradability is a further
follow-on.

---

## Sequencing

1. **Item 1 primitive** first — self-contained, small, likely a quick
   win now that the attribute-bit bug is identified; delivers a
   persistent monotonic counter and the `NV_ReadPublic` diagnostic
   pattern reusable for Item 2.
2. **Item 2** next — reuses the session/auth marshalling muscle from
   Item 1 and the existing `pcr_policy_digest` math.
3. **Cross-repo follow-ons** last — secure-log checkpoint-binding for the
   counter (Item 1) and `PolicyAuthorize` upgradability (Item 2).

Both items are validated on the real vTPM in-process; the `tpm-hw`
(tss-esapi) equivalents remain separate and need physical hardware.
