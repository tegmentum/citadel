# Citadel: Mesh-Sealed Secrets (MSS) — Decisions & Roadmap

Status: Plan
Project: Citadel
Audience: Architecture, Security, TPM
Related: `mesh-sealed-secrets.md` (the design this scopes),
`distributed-attestation-mesh.md`, `measured-state-transitions.md`,
`control-plane-roadmap.md` (the quorum + audit machinery this reuses).

MSS makes secret access governed by the **continuous agreement of the mesh**
rather than one machine's claim. This scopes it onto what Citadel already has —
and most of it already exists. This document first **makes the open design
calls**, then phases the work.

---

## The calls

### C1 — No continuous custodian (not "optional threshold"). The MVP property is honest.
The design frames threshold crypto (§10) as optional while claiming "no single
point of trust" (§18). Those are in tension: a non-threshold scheme where a
custodian holds plaintext and releases it on a yes-vote **is** a single point.

**Decision — two custody models for two use-cases, neither with a continuous
custodian:**
1. **Seal-to-the-requester's-own-TPM under a mesh-gated policy (the MVP, common
   case).** The secret is sealed so the requester's *own* TPM holds the blob, but
   can only **unseal when the live mesh authorizes** it. No separate custodian
   exists; revocation = the mesh stops authorizing → the node physically holds the
   blob but can't open it. The only trust is at *provisioning* (whoever sealed it
   once), not continuously.
2. **Threshold mode (distributed HSM, §16) for "plaintext must never exist on one
   node ever"** — signing keys, CA material. The secret is *operated on*
   collectively (sign/decrypt) and never reassembled. This is a distinct
   capability, not the gate for ordinary access.

So §18's claim is true *with this mechanism*; the earlier framing was not. MVP
property = **quorum-gated, leased release with revocation and audit, no continuous
custodian**; threshold mode adds **no node ever holds the full key**.

### C2 — Mesh→unseal binding = quorum-as-PolicyAuthorize-authority.
The TPM can't evaluate "does the mesh agree", so the mesh gates the **delivery of
an unseal authorization**, exactly as `tpm-core` already does for *signing*
(`approve_policy` / `sign_authorized` = TPM2 PolicyAuthorize). The secret is
sealed under a policy that requires an authority approval; **the authority is the
secret's assigned-witness quorum**, and the approval is bound to
`(secret_id, requester, nonce, lease_expiry)`. Unseal needs a *live* quorum
authorization → mesh-gated and replay-bound. This is the centerpiece; it is a
small extension of an existing primitive, not new cryptography.

### C3 — Categorical witness-agreement gates release; the numeric trust score does not.
§6/§9 propose a 0–100 score and weighted-trust-sum quorum. This reintroduces the
scalar the mesh design deliberately rejected ("agreement-first — never a bare
number; show *who* agrees and *why*"). A score hides the disagreement structure,
is gameable, and begs "scored by whom".

**Decision:** release requires **k-of-n assigned witnesses** to APPROVE, where a
witness APPROVES iff it *independently* classifies the requester `Trusted` (the
existing `Verdict::Pass` + `quorum_threshold` machinery). The numeric score, if
shown at all, is a **dashboard triage aid**, never a gate input. Weighted-by-score
quorum is rejected.

### C4 — Availability: lease-during, deny-at-renewal, bounded quorum set, opt-in break-glass.
Quorum-per-renewal risks a partition turning into a secrets outage.

**Decision:** (a) a running node **keeps** access for its current lease;
revocation takes effect at the **next renewal**, so a transient partition breaks
new releases/renewals, not live workloads mid-lease. (b) A secret's quorum is over
its **assigned witness set** (k-of-n of a *bounded* HRW set), so availability needs
only k of n reachable, not the whole fleet. (c) An explicit, loudly-audited
**break-glass**: a secret policy MAY allow an emergency lease extension signed by
escrow officers (§15) when quorum is unreachable — opt-in per secret class.

### C5 — Freshness + cold-start reuse existing mechanisms.
Freshness: the release vote is over a **nonce-bound** quote (reuse the attestation
challenge nonce); the authorization is bound to `(nonce, lease_expiry)` and
single-use — a replayed healthy-state quote fails. Cold-start: a new node at
`Probationary` may access a designated **bootstrap secret class** (low value, e.g.
its own service cert) under relaxed quorum; high-value classes require `Trusted`,
earned over the existing probation window (reuse `promotion`).

---

## What already exists (reuse, not rebuild)

| MSS need | In the codebase |
|---|---|
| TPM seal / unseal | `TpmBackend::seal(data, policy_digest)` / `unseal` (mock + hardware) |
| PolicyAuthorize binding (C2) | `TpmBackend::approve_policy` / `sign_authorized` — authority-approved policy, already used for measured-state signing |
| Quorum assignment (bounded set) | `witness::assign` (HRW) — key it on `secret_id` |
| Signed quorum votes + tally | `AttestationResult`, `quorum_threshold`, and the M2 `propose → vote → tally → enact` flow (the release flow is isomorphic) |
| Categorical trust (C3) | `TrustState` + witness agreement |
| Decision audit, witnessed + replicated (your §20.8) | the operator-audit hash-chain + evidence chain |
| Share placement across nodes | `assign_holders` (HRW) |
| Mesh-sealed service identity (§13) | `tpm-tls::TpmTlsIdentity` (TPM-held keys, E2) — add the quorum gate before minting |
| Lease heartbeat (§12) | the periodic re-attestation loop (`attestation_interval`) |
| Cold-start tiers (C5) | `promotion` (probation → trusted) |

---

## Phases

| # | Item | Track | Effort | Gating |
|---|------|-------|--------|--------|
| S0 | tpm-core: `unseal_authorized` (PolicyAuthorize for sealing) | TPM prereq | ✅ done (mock; hardware via tss-esapi later) | no |
| MSS1 | Secret authority + release protocol | Core | ✅ done (mock-backed; real-TPM bind = S0) | — |
| MSS2 | Leases + revocation | Core | ✅ done | MSS1 |
| MSS3 | Gossip-wire the release protocol into `Node` | Mesh | ✅ done | MSS1 |
| MSS4 | Decision audit + dashboard "Secrets" view | Read | ✅ done | MSS1, CP4 |
| MSS5 | Mesh-sealed service identity (gate `tpm-tls` minting) | Identity | ✅ done | MSS1, E2 |
| MSS6 | Threshold custody (Shamir) | Crypto | ✅ done | MSS1 |
| MSS6b | Threshold signing (FROST) | Crypto | ✅ done (+ DKG + distributed session) | MSS6 |
| MSS7 | Escrow + break-glass + bootstrap class | Ops | ✅ done | MSS1, MSS2 |

**MVP = S0 + MSS1 + MSS2** — quorum-gated, leased release with revocation and
audit. That covers all eight of the design's §20 success criteria except the
threshold/HSM extension (MSS6).

### S0 — tpm-core: quorum-authorized unseal
* **Goal:** unseal only when an authority approved the policy — the C2 binding.
* **Scope:** mirror `sign_authorized` for unsealing: `unseal_authorized(sealed,
  authority_pub, approved_policy, policy_ref, approval_sig)` — unseal iff the
  authority signed `H(approved_policy ‖ policy_ref)` and (for hardware) the live
  state satisfies it. Mock models it; hardware via tss-esapi PolicyAuthorize later.
* **Seam:** `tpm-core/src/backend/traits.rs` + `mock.rs`/`hardware.rs`.
* **Test:** unseal succeeds with a valid authority approval, fails without / with a
  wrong approval.

### MSS1 — secret authority + release protocol  (core)
* **Goal:** a secret opens iff a quorum of its assigned witnesses *currently*
  approve, each iff it independently trusts the requester; freshness-bound.
* **Scope:** `SecretPolicy` (id, version, quorum k-of-n, `min_trust = Trusted`,
  lease); `ReleaseRequest` (secret_id, requester, nonce, tick — signed);
  `ReleaseVote` (witness signs APPROVE iff it sees the requester `Trusted`);
  `ReleaseAuthorization` (≥k votes, nonce-bound); `SecretAuthority::seal` (under a
  policy keyed to the assigned-witness set) + `open` (verify authorization → S0
  unseal). Quorum set = `witness::assign(NodeId(secret_id), roster, epoch, n)`.
* **Seam:** new `citadel-mss` crate over `citadel-mesh` (witness, crypto) +
  `tpm-core` (S0).
* **Test:** trusted requester + k approvals → opens; a tampered/distrusted
  requester gets < k approvals → denied; a replayed (old-nonce) authorization is
  rejected.

### MSS2 — leases + revocation
* **Goal:** continuous governance (§11, §12) — access is a lease, not forever.
* **Scope:** lease TTL per secret; renewal requires a fresh request + quorum;
  C4 "keep-during, deny-at-renewal" semantics; trust-drop → next renewal denied.
* **Test:** a lease expires → re-request needed; a node whose trust drops mid-lease
  keeps access until expiry, then is denied (revocation by withholding renewal).

### MSS3 — gossip-wire the release protocol
* **Goal:** run the protocol live in the mesh, like M2 did for quarantine.
* **Scope:** `GossipMessage::{ReleaseRequest, ReleaseVote}`; `Node` collects votes
  for secrets it witnesses, tallies, and emits the authorization — structurally the
  quarantine flow (`propose_and_broadcast` / receipt handlers / `tally_and_*`).
* **Test:** a harness mesh releases a secret to a trusted node and denies a
  tampered one, end to end over gossip.

### MSS4 — decision audit + dashboard
* **Goal:** every release decision witnessed + replicated (your §20.8) and visible.
* **Scope:** release decisions as audit-chain records (reuse the operator-audit
  chain + the agreement object); a dashboard "Secrets" view (who requested, the
  quorum, approve/deny + reasons).
* **Test:** a release + a denial each yield a verifiable decision record; the view
  renders the quorum tally.

### MSS5 — mesh-sealed service identity
* **Goal:** TLS certs / JWT keys / DB creds minted only on a release decision (§13).
* **Scope:** gate `tpm-tls` cert minting (E2) on an MSS release for the identity's
  secret class; the key stays TPM-held.
* **Test:** a node gets its mesh-TLS identity only after quorum approval; a
  distrusted node is refused.

### MSS6 — threshold mode / distributed HSM
* **Goal:** the C1 "no node ever holds the full key" property (§10, §16).
* **Scope:** Shamir `k`-of-`n` sharing; each share TPM-sealed + placed by
  `assign_holders`; threshold signing/decryption so the key is never reassembled.
  Genuinely new crypto — a separate, deliberate track.
* **Test:** a k-of-n signature/decryption succeeds with k honest holders; k-1
  cannot; no node ever materialises the full key.

### MSS7 — escrow + break-glass + bootstrap class
* **Goal:** the C4/C5 edges — emergencies, partitions, cold-start.
* **Scope:** N-of-M officer escrow (§15) + mesh quorum for recovery secrets; the
  opt-in break-glass lease extension; the `Probationary` bootstrap secret class.
* **Test:** escrow release needs both officers + quorum; break-glass is audited
  loudly; a probationary node gets only the bootstrap class.

---

## Success criteria (design §20) → coverage

1. Three TPM nodes form a mesh — existing.
2. Exchange attestation evidence — existing.
3. Trust computed — existing (categorical, C3).
4. Release requires quorum — **MSS1**.
5. Trust degradation prevents release — **MSS2** (deny-at-renewal).
6. Leases expire automatically — **MSS2**.
7. Compromise simulation → denial — **MSS1 + MSS2** (harness test).
8. Decisions witnessed + replicated — **MSS4** (audit chain).
