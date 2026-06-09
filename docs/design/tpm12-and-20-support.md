# Supporting both TPM 1.2 and TPM 2.0

**Status:** Plan

Citadel targets TPM 2.0 today. Some fielded hardware (older servers, embedded,
edge) ships only a **TPM 1.2**. To run Citadel's trust fabric on that hardware we
need 1.2 support — but 1.2 is not a subset of 2.0 with fewer commands; it is a
different, more limited device. This plan records what carries over, what cannot,
and how the codebase adapts without compromising the 2.0 path.

## The gap (why 1.2 is not just "2.0 minus features")

| Capability | TPM 1.2 | TPM 2.0 (today) |
|---|---|---|
| PCR hash bank | SHA-1 only | SHA-256/384, agile, multi-bank |
| Asymmetric keys | RSA only (2048) | RSA + ECC (P-256/384) |
| Quote | `TPM_Quote` / `Quote2`, SHA-1 composite | `TPM2_Quote`, bank-tagged, agile |
| Enhanced Authorization | none (PCR/AuthData only) | policy sessions (PolicyPCR, **PolicyAuthorize**, PolicySigned, …) |
| Sealing | bind/seal to PCRs + authData | `TPM2_Create` under a policy digest |
| NV | limited | rich (counters, policies, attributes) |
| Endorsement | single EK | EK + flexible hierarchies |

The consequences for Citadel features:

- **Measured boot + attestation** — works on 1.2 (SHA-1 PCRs, RSA AK, `TPM_Quote`).
  The mesh's witness model is hash-agnostic; verifiers just need the quote +
  reference values for the device's bank.
- **MMA / IMA** — works, but SHA-1 only on 1.2 (weaker; flag it).
- **MSS (S0 `unseal_authorized`, PolicyAuthorize)** — **not available on 1.2**
  (no policy sessions). 1.2 can seal to PCR state + authData, so quorum-gated
  release falls back to the app-layer gate (MSS `open`) without the TPM-enforced
  PolicyAuthorize binding.
- **tpm-tls / EC identities** — 1.2 is RSA-only; identities must be RSA on 1.2.
- **Threshold signing (FROST/Ed25519)** — unaffected (software, not the device).

So 1.2 is a **degraded-but-useful** tier: attestation + RSA identities + SHA-1
measured boot, without TPM-enforced policy sealing or EC.

## The abstraction — capability advertisement + graceful degradation

The codebase is already shaped for this: `TpmBackend` is a trait, and the
2.0-only operations (`unseal_authorized`, `approve_policy`, `sign_authorized`)
**default to `bail!`**. We extend that pattern deliberately rather than
special-casing 1.2 everywhere.

1. **Spec version + capabilities on `BackendStatus`.** Add `spec_version`
   (`Tpm12` | `Tpm20`) and a `Capabilities { banks: Vec<HashAlg>, key_algs,
   policy_sessions: bool, policy_authorize: bool }`. The backend reports what it
   can do; the device is the source of truth, not a compile flag.

2. **Capability gating in the command/issuance layer.** Commands check the
   advertised capability before attempting a 2.0-only path and either pick a 1.2
   route or fail with a clear message — e.g. `citadel tpm key create` defaults to
   RSA and rejects `--algorithm ecc-p256` on a 1.2 device; MSS release on 1.2 uses
   the app-layer gate and the operator-visible decision is annotated
   `tpm_enforced=false`.

3. **A `Tpm12Backend`.** Implement the trait against a TPM 1.2 stack
   (TrouSerS/TSS 1.2 via a C shim, or a maintained Rust 1.2 client) for the
   supported subset — `create_key` (RSA), `sign`, PCR read/extend (SHA-1),
   `TPM_Quote`, NV read/write, seal/unseal to PCR+authData. Everything 2.0-only
   inherits the default `bail!`. Selectable via `--backend device12` /
   auto-detection (TIS at `/dev/tpm0` reporting 1.2).

4. **Verifier-side bank agnosticism.** The mesh already carries `(bank, index)`
   on measurements/quotes; ensure reference manifests and the control-plane
   rollups handle a `sha1` bank as a first-class (if weaker) bank, surfaced in the
   observability layer (`citadel:ima-policy`, the trust gauge) so operators can
   see which nodes are on the weaker tier.

## Feature matrix (what a 1.2 node gets)

| Citadel feature | 1.2 | 2.0 |
|---|---|---|
| Mesh membership + gossip | ✅ | ✅ |
| Measured-boot attestation (quote) | ✅ (SHA-1, RSA) | ✅ |
| Witness-quorum trust + quarantine | ✅ | ✅ |
| SPIFFE/SPIRE identity gating | ✅ | ✅ |
| RSA service identity (tpm-tls) | ✅ | ✅ |
| ECC identity | ❌ (RSA only) | ✅ |
| MSS quorum-gated release (app-layer) | ✅ | ✅ |
| MSS TPM-enforced PolicyAuthorize (S0) | ❌ | ✅ |
| Threshold custody / signing (MSS6/6b) | ✅ (software) | ✅ |
| Observability / containment telemetry | ✅ | ✅ |

A 1.2 node participates fully in the trust fabric and gets attested identity; it
is marked a weaker tier (SHA-1, no TPM-enforced sealing) so policy can require 2.0
for high-value secrets.

## Phases

| Phase | Scope |
|---|---|
| T1 | ✅ done. `BackendStatus.spec_version` + `Capabilities` (banks/ecc/policy_sessions/policy_authorize); mock/hardware/vtpm report `Tpm20`; `service::create_key` rejects unsupported algorithms with a clear error; `citadel tpm status` shows the spec tier. No behavior change for 2.0. |
| T2 | `Tpm12Backend` (RSA keys, SHA-1 PCRs, `TPM_Quote`, seal-to-PCR, NV) via a 1.2 TSS shim, behind a `tpm12` feature. Auto-detect TIS 1.2 devices. |
| T3 | ✅ done (in-tree). `hash_for_bank` now first-class for `sha1` (1.2) + `sha384`, so measured boot / IMA / reference manifests work on the SHA-1 bank; `NodeTrustView` gains `tpm_spec` + a `citadel:tpm-spec=<2.0|1.2>` selector so policy can require 2.0. Spec now gossips end to end: a node advertises its tier (Node::set_tpm_spec from the backend, wired in build_node_with_backend) → MemberUpdate.tpm_spec → CP NodeRecord → spiffe_node_view → the selector auto-populates. |
| T4 | Docs + a 1.2 conformance test (against a 1.2 simulator where available) mirroring the swtpm 2.0 path. |

The 2.0 path is unaffected throughout: 1.2 is added as a capability-gated tier,
not a rewrite.
