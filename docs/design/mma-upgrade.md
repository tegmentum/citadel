# Design: Upgrading the MMA agent (Citadel) without bricking signing

Status: Implemented (PolicyAuthorize + witness-logged approvals, vTPM-validated)
Related: `measured-merkle-anchoring.md`, `tpm-nv-counter-and-policy-signing.md`

## The problem

The MMA signing key can be **bound to a measured state** (`tpm identity
init --pcr-bind <pcrs>`): the TPM only signs a checkpoint while those PCRs
match the values at key creation. Self-enrollment (`tpm measure enroll
--pcr 14`) folds Citadel's *own binary hash* into a PCR, so the signing
key is effectively bound to "this exact Citadel binary."

That is exactly what we want for integrity — and exactly what breaks on
**upgrade**. A new Citadel build has a different hash → PCR 14 changes →
the bound key's `authPolicy` (a fixed PolicyPCR digest) can no longer be
satisfied → `TPM2_Sign` returns `TPM_RC_POLICY_FAIL`. The key is "bricked"
for the new binary. The same applies to any TCB change the bound PCRs
cover (kernel, firmware), not just Citadel itself.

So: **how do we roll out a new agent/Citadel and keep signing?**

## Threat model: an upgrade looks exactly like an attack

Measurement is blind to intent. A hash says "the state is X"; it can never
say "X is good." A legitimate upgrade and a malicious tamper are therefore
the **same observable event** — a change to a previously-unapproved
measurement. The only thing that distinguishes them is **authorization**:
an upgrade is an attack that an authority signed off on.

Two hard consequences:

1. **Don't try to tell them apart at measurement time — you can't.** All
   security collapses onto the approval layer. The design's job is to make
   every *authorized* state change hard to forge and fully attributable,
   not to make the TPM "smarter" about intent.
2. **The authority key is the crown jewel.** If it is compromised, attacks
   become indistinguishable from upgrades by construction. So it must not
   be a single online key:
   - **offline / HSM**, ideally **M-of-N quorum** (one compromise is not
     enough);
   - approvals **transparency-logged**, not merely verified — recorded in
     an append-only, **witnessed** log (the CT / Sigstore model) so even a
     coerced/compromised authority leaves public evidence and a bad
     "upgrade" is detectable after the fact;
   - **reproducible builds + source provenance**, so the approved digest
     is verifiable from public source, not opaque.

This reframes the whole mechanism:

- **PolicyAuthorize is the enforcement** — the TPM refuses to sign for any
  state no authority approved.
- **The witnessed approval log is the detection** — an approval that
  should not exist is publicly visible; an *unapproved* state change is
  exactly the one with **no valid, witnessed approval** in the log. You
  don't detect the attack by the measurement; you detect it by the absence
  of a logged authorization for that measurement.

MMA is already positioned for this: the log records the `agent.enroll`
event (the new measurement); fold the **approval** in beside it (the
secure log is already witness-able) and an upgrade becomes an attributable
record — "approved by ⟨quorum⟩ at ⟨time⟩, reproducible from ⟨source⟩,
witnessed at ⟨height⟩." This should drive the PolicyAuthorize design below:
approvals are quorum-signed and land in the witnessed MMA, not just handed
to the TPM.

## Recommended answer: PolicyAuthorize (an upgradable policy)

TPM 2.0's canonical mechanism for this is **`TPM2_PolicyAuthorize`**.
Instead of binding the key to a *fixed* PolicyPCR digest, bind it to a
**policy authority public key**:

- `authPolicy = PolicyAuthorize(authority_pubName)` — the key may be used
  under *any* policy that the **authority key** has signed.
- At sign time, Citadel runs `TPM2_PolicyPCR` (live PCRs) then
  `TPM2_PolicyAuthorize`, presenting a **signed approval** (`authority`
  signature + ticket) over the *current* PolicyPCR digest. If the
  authority approved this state, the session is satisfied and the TPM
  signs. The signing key itself **never changes across upgrades**.

This cleanly decouples two things that are conflated in `--pcr-bind`:

| | `--pcr-bind` (fixed) | `PolicyAuthorize` (upgradable) |
|---|---|---|
| What may sign | one frozen PCR state | any authority-approved state |
| Upgrade | re-key required | sign a new approval, key unchanged |
| Trust root | the TPM key | the **offline authority key** |

### The upgrade ceremony

The authority key is held **offline / by the release operator** (HSM,
air-gapped, or a separate hardware TPM). To ship a new Citadel:

1. **Build** the new Citadel; compute its measurement (and the expected
   TCB PCR digest it produces).
2. **Approve**: the operator signs the new PolicyPCR digest with the
   authority key → an *approval blob* (`approvedPolicy` + signature),
   distributed alongside the release.
3. **Deploy** the new binary. On start it runs `measure enroll
   --verify-ima` (records the new digest into the MMA, IMA-corroborated)
   and, when signing, presents the approval blob to satisfy
   PolicyAuthorize.
4. The **MMA log is continuous**: the same key keeps signing, the
   hash-chain/`prev_checkpoint` links across the upgrade, and the NV
   anti-rollback counter keeps advancing. The upgrade itself appears as a
   measured `agent.enroll` event in the log — so a verifier sees *when*
   the agent changed and to *what*, with provenance.

Revocation of an old build = stop publishing (and optionally rotate the
authority key, which invalidates all prior approvals at once).

## Alternatives (and why PolicyAuthorize wins)

- **Key rotation** (`tpm identity rotate` already exists): on upgrade,
  create a *new* signing key bound to the new state and have the old key
  sign an attestation of the new key. Works, but breaks "same key"
  continuity, complicates verifier trust (must follow the rotation
  chain), and every upgrade is a key ceremony. Fine as an interim; worse
  long-term.
- **PolicyOR** over allowed states: bind to a disjunction of old∨new
  digests. Grows unbounded, needs every future state known in advance —
  not viable for open-ended upgrades.
- **Don't bind the key; rely on the citadel-side gate + IMA**: keep the
  signing key on the password path, and depend on `--require-baseline`
  (software gate) plus the IMA-corroborated enrollment for assurance.
  This is the *current default* and upgrades "just work" (re-enroll,
  re-baseline) — but the gate isn't TPM-enforced, so a tampered agent
  could bypass it. Acceptable when IMA-appraisal already enforces the
  binary from below.

## What to do today (before PolicyAuthorize lands)

Upgrades are already supported, with a deliberate trade-off:

- **Unbound signing key (default):** upgrade Citadel, run `measure enroll
  --verify-ima` (new digest, IMA-corroborated), `pcr baseline save` the
  new state, and `measure sign --require-baseline <new>`. The MMA, NV
  counter, and log chain are continuous. Enforcement is citadel-side +
  IMA — not TPM-hard.
- **Bound signing key (`--pcr-bind`):** an upgrade requires an explicit
  **re-enrollment ceremony** — `identity rotate` (or recreate) the
  signing identity bound to the new measured state. Plan for this until
  PolicyAuthorize removes the re-key.

## Implementation status & remaining wiring

### DONE — the TPM protocol (`feat(vtpm): TPM2_PolicyAuthorize ...`)

The backend half is implemented and validated in-process on the real vTPM:

- `create_authority_key` — external-loadable approver key.
- `create_key_authorized(authority_pub)` — key with `authPolicy =
  PolicyAuthorize(authorityName)`.
- `approve_policy(authority, approvedPolicy, policyRef)` — the authority
  signs `H(approvedPolicy ‖ policyRef)`.
- `sign_authorized(...)` — `LoadExternal(authority, OWNER)` →
  `VerifySignature` → ticket → `StartAuthSession` + `PolicyPCR` +
  `PolicyAuthorize` → `Sign`.

Test proves: an authorized key signs in an approved state, the TPM refuses
an unapproved state, and after the authority approves a NEW state the SAME
key signs again (the upgrade, no re-key). Two bring-up bugs fixed:
VerifySignature is NO_SESSIONS (ticket at offset 10); the authority must
load under a real hierarchy (OWNER), which needs its public's
fixedTPM/fixedParent clear.

### DONE — CLI + witness-logged approvals + signer integration

All five pieces are implemented and validated end-to-end on the real vTPM
(`authorized_key_signs_only_after_witnessed_approval_vtpm`) and with the
mock backend (same-named, no `_vtpm` suffix):

1. **`public_blob(handle)`** backend method (portable authority public) +
   vTPM override (extracts the stored `public` blob) and **mock impls** of
   the four PolicyAuthorize methods for a software test path.
2. **Authority + binding (CLI)** — `tpm identity init <auth> --authority`
   (via `create_authority_key`, recorded as `{policy_authority: true}`);
   `tpm identity init <name> --authorized-by <auth> --pcr-bind <pcrs>` (via
   `create_key_authorized`, recording `{policy_authorize: {authority, bank,
   indices}}` in the key object metadata). `--authorized-by` requires
   `--pcr-bind`; `--authority` is exclusive with both.
3. **`tpm policy approve --authority <auth> --pcr <pcrs>`** — computes the
   live PolicyPCR digest, `approve_policy` with the authority key, and
   **appends the approval to the witnessed MMA log** (`measurement` stream,
   event `policy.approve`, payload `{approved_policy, policy_ref,
   signature, authority, bank, indices}`). The transparency half: approvals
   are public, append-only, witness-able, not merely handed to the TPM.
4. **Signer integration** — in `TpmCheckpointSigner::sign_checkpoint`, a
   PolicyAuthorize-bound identity (metadata `policy_authorize`) resolves the
   authority pub, computes the live PolicyPCR digest `V`, scans the MMA log
   for the latest `policy.approve` whose `approved_policy == V`, and calls
   `sign_authorized` with that approval. **No valid logged approval for `V`
   ⇒ no signature** (the detection signal — an unapproved state is exactly
   the one with no witnessed authorization).
5. **Provenance** — `attest verify` surfaces an `approval:` line:
   the approving authority, the bound PCRs, and whether the live measured
   state carries a witnessed approval (`ApprovalProvenance`).

The TPM signing key never changes across upgrades: an upgrade is a new
`policy.approve` in the log, not a re-key.
