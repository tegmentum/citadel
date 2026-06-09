# Citadel

Citadel is a **TPM-backed distributed trust platform**: it roots trust in each node's hardware TPM, agrees on that trust across a mesh, and uses it to gate secrets, workload identity, and containment — with a full observability plane over the whole fabric. Identity and access become *continuously earned* properties of a node, not one-time admissions.

At its base is **`citadel tpm`**, an operator-friendly TPM toolkit (a resource-oriented replacement for low-level `tpm2-tools`). On top of it Citadel runs an attestation mesh, a verifying control plane, Mesh-Sealed Secrets, SPIFFE/SPIRE identity, and Prometheus/OpenTelemetry observability. It supports TPM 2.0 and, as a capability-gated tier, TPM 1.2.

## The platform

| Layer | What it does | Reference |
|---|---|---|
| **TPM toolkit** — `citadel tpm` | Named objects, declarative policies, measured boot, sealing, remote attestation, a tamper-evident audit log, and the Measured Merkle Anchor. | this README; `tpm-core`, `tpm-tui` |
| **Attestation mesh** — `citadel-mesh` | SWIM gossip + HRW witness assignment; nodes attest each other and reach **witness-quorum trust** (categorical, signed verdicts), with gossip-wired quarantine + Reed-Solomon evidence on compromise. | [`distributed-attestation-mesh.md`](docs/design/distributed-attestation-mesh.md) |
| **Control plane** — `citadel-control-plane` | A **verifying aggregator** (explicitly *not* a root of trust): re-verifies every verdict, derives trust, serves an agreement-first dashboard + API over pluggable durable storage (Mem/redb/Postgres) with HRW sharding. Load-verified at **10k nodes (~19k verdicts/s)**. | [`control-plane-roadmap.md`](docs/design/control-plane-roadmap.md) |
| **Mesh-Sealed Secrets** — `citadel-mss` | Quorum-gated, lease-bound, TPM-enforced secret release; threshold custody (Shamir) and threshold signing (FROST + DKG) carried over mesh gossip. | [`mss-roadmap.md`](docs/design/mss-roadmap.md) |
| **Workload identity** — `citadel-spiffe`, `citadel-spire-*`, `citadel-trust-sync` | Mesh trust gates SPIRE SVID issuance: a NodeAttestor plugin (with AutoMTLS + the agent pair), a registration controller, and a continuous trust synchronizer that revokes on quarantine. | [`spiffe-roadmap.md`](docs/design/spiffe-roadmap.md) |
| **Observability** — `citadel-otel-schema`, `-metrics-exporter`, `-telemetry` | Security-state Prometheus `/metrics`, OpenTelemetry logs + the containment trace, plus tool-validated alert rules / Grafana dashboards / Collector config and multi-cluster federation. | [`observability-roadmap.md`](docs/design/observability-roadmap.md) |

The mesh and control plane are queryable from the CLI via **`citadel cluster`** (below). The rest of this README documents the `citadel tpm` toolkit; see the per-layer design docs above for the trust fabric.

## Why the TPM toolkit

The existing TPM toolchain is powerful but hostile. Common workflows require explicit context file management, manual command sequencing, opaque error codes, and deep spec knowledge. `citadel tpm` makes the TPM feel like a managed object store:

- **Named objects** instead of context files and raw handles
- **Workflow collapsing** — `citadel tpm key create` does the right create/load/persist sequence
- **Explainable diagnostics** — cause chains, context, actionable next steps
- **Structured output** — `--json` or `--format yaml` on every command
- **Declarative policies** — YAML policy files compiled and tested before use
- **Auto-detection** — finds hardware TPM, vTPM, or falls back to mock

## Install

```bash
bash install.sh
```

This builds a release binary with vTPM support, installs it to `~/.local/bin/citadel`, installs the libtpms WASM component to `~/.local/share/tpm/` (from a local libtpms-wasm build if present, otherwise downloaded from the [libtpms-wasm](https://github.com/tegmentum/libtpms-wasm) release), and sets up shell completions.

### From source (manual)

```bash
cargo build --release --features vtpm
cp target/release/citadel ~/.local/bin/
```

### Shell completions

```bash
citadel tpm completions zsh  > ~/.zsh/completions/_citadel
citadel tpm completions bash > ~/.local/share/bash-completion/completions/citadel
citadel tpm completions fish > ~/.config/fish/completions/citadel.fish
```

## Quick start

```bash
citadel tpm init
citadel tpm key create signing/release
citadel tpm key sign signing/release --input artifact.tar.gz
citadel tpm key list
citadel tpm --json status
citadel                             # launches TUI
```

## Backends

The `--backend` flag (or `TPM_BACKEND` env var) selects the TPM backend. Default is `auto`.

| Backend | Description |
|---------|-------------|
| `auto` | Probe in order: hardware TPM, vTPM, mock (default) |
| `device` | Hardware TPM at `/dev/tpmrm0` (requires `--features tpm-hw`) |
| `vtpm` | In-process libtpms via WASM/wasmtime (requires `--features vtpm`) |
| `mock` | Deterministic in-memory mock for development |
| `tpm12` | Software-modeled **TPM 1.2** tier (RSA-only, SHA-1 PCRs, no policy sessions) — exercises the 1.2 device class |

Auto-detection checks for `/dev/tpmrm0` first, then looks for the vTPM component at `~/.local/share/tpm/tpm-ephemeral.component.wasm`, and falls back to mock if neither is found.

The vTPM persists its state alongside the metadata store at `<store>.tpmstate`, so keys, NV, and saved PCRs (0–15) survive across separate `citadel tpm` invocations — signing, sealing, attestation, and seal-to-attested-set work end-to-end on the virtual TPM, not just the mock. Permanent state restores on startup; volatile state (PCRs/sessions) is checkpointed with `Shutdown(STATE)` and resumed with `Startup(STATE)`. Note that PCRs 16–23 are resettable and not in the save set, so use a PCR in 0–15 when you need a measurement anchor to persist across invocations.

## Command groups

`citadel` is the umbrella CLI:

- **`citadel tpm <…>`** — the TPM operator platform (everything documented below).
- **`citadel cluster <…>`** — operator queries against the Citadel control plane
  (the mesh trust fabric): `status` (mesh health), `nodes`, and `metrics`
  (Prometheus exposition). Point it at the control plane with `--endpoint` or
  `CITADEL_CONTROL_PLANE`.

```bash
citadel cluster status   --endpoint http://control-plane:8080
citadel cluster nodes    --endpoint http://control-plane:8080
citadel cluster metrics  --endpoint http://control-plane:8080
```

## Commands

### Workspace

```bash
citadel tpm init [--profile <name>]        # initialize workspace
citadel tpm status                         # backend + workspace + health score
citadel tpm doctor                         # diagnostic health checks
citadel tpm capabilities                   # algorithms, PCR banks, limits
citadel tpm debug --output bundle.json     # collect diagnostic bundle
citadel tpm workspace info                 # workspace summary
citadel tpm workspace export --output f    # export metadata to JSON
citadel tpm workspace import --input f     # import metadata from JSON
```

### Keys

```bash
citadel tpm key create signing/release [--algorithm ecc-p256] [--policy boot-policy]
citadel tpm key list [--json]
citadel tpm key show signing/release
citadel tpm key sign signing/release --input file.bin [--output sig.bin]
citadel tpm key delete signing/release
citadel tpm key export-pub signing/release [--export-for openssl|ssh|cosign|pkcs11]
citadel tpm key rotate signing/release
```

### Secrets

```bash
citadel tpm secret seal db/password --input secret.txt [--policy boot-seal]
citadel tpm secret unseal db/password [--output recovered.txt]
citadel tpm secret list
```

### Remote attestation

```bash
citadel tpm attest ak-create attest/main
citadel tpm attest quote --ak attest/main --pcr 0,7,11 --nonce challenge --output quote.json
citadel tpm attest verify --quote quote.json --nonce challenge
```

### NV storage

```bash
citadel tpm nv define config/build-id --size 64
citadel tpm nv write config/build-id --input data.txt
citadel tpm nv read config/build-id [--output data.txt]
citadel tpm nv list
citadel tpm nv delete config/build-id
```

### PCR operations

```bash
citadel tpm pcr show --bank sha256 --index 0,7,11
citadel tpm pcr baseline save clean-boot --index 0,7,11
citadel tpm pcr baseline diff clean-boot
citadel tpm pcr baseline list
```

### Policies

```bash
citadel tpm policy create boot-policy --pcr 7,11 [--password]
citadel tpm policy compile policy.yaml
citadel tpm policy test boot-policy
citadel tpm policy explain boot-policy
citadel tpm policy show boot-policy
citadel tpm policy list
citadel tpm policy delete boot-policy
citadel tpm policy approve --authority release --pcr 14   # approve the live measured state for PolicyAuthorize-bound keys
```

Policy YAML format:

```yaml
name: boot-integrity
requires:
  pcr:
    - index: 7
    - index: 11
  auth_value: true
```

### Objects

```bash
citadel tpm object list
citadel tpm object tree
citadel tpm object dependents signing/key
citadel tpm object rename old/name new/name
citadel tpm object retire signing/old
citadel tpm object activate signing/old
```

### Profiles

Profiles are mutable defaults applied to new operations. They can include constraints that enforce algorithm restrictions, path prefixes, and approval requirements.

```bash
citadel tpm profile list
citadel tpm profile show [name]
citadel tpm profile set ci-signer
```

### Identities

An identity bundles a backing key, an intended usage, an optional policy, and certificate metadata into one named object. Audit checkpoint signing references identities by name.

```bash
citadel tpm identity init auditor [--usage code-signing] [--algorithm ecc-p256] [--policy boot-policy]
citadel tpm identity show auditor
citadel tpm identity list
citadel tpm identity rotate auditor
citadel tpm identity delete auditor
```

A signing key can be bound to a measured state so the TPM itself refuses to sign unless the host matches it:

```bash
citadel tpm identity init anchor --pcr-bind 14                       # frozen: signs only while PCR 14 matches creation time
citadel tpm identity init release --authority                        # an offline PolicyAuthorize approver (the upgrade root)
citadel tpm identity init anchor --authorized-by release --pcr-bind 14   # upgradable: signs any state `release` has approved
```

`--pcr-bind` freezes the key to one PCR state (an upgrade would brick it). `--authorized-by` binds it to an authority key instead (TPM2_PolicyAuthorize): the same key keeps signing across upgrades, gated on a witnessed approval — see [Measured Merkle Anchor](#measured-merkle-anchor-mma) below.

### Secure audit log

`citadel tpm audit` is a tamper-evident secure log: entries are hash-chained, sealed into Merkle-rooted segments, and checkpoint-signed by a TPM-backed identity. An anti-rollback head file guards against truncation, payloads can be envelope-encrypted under a master KEK, and segment heads can be co-signed by an external witness. Multiple independent streams (each with a confidentiality tier) are supported.

```bash
citadel tpm audit append --event user.login --payload "session opened"   # append a hash-chained entry
citadel tpm audit head                                  # highest seqno for a stream
citadel tpm audit show 1                                # read an entry by seqno
citadel tpm audit chain verify                          # verify the hash chain
citadel tpm audit segments close                        # seal the open window into a Merkle segment
citadel tpm audit sign --identity auditor 1             # TPM-sign a closed segment's checkpoint
citadel tpm audit verify                                # verify the checkpoint chain from genesis to head
citadel tpm audit prove 1                               # build a Merkle inclusion proof for an entry
citadel tpm audit rollback                              # check the anti-rollback head file vs the database
citadel tpm audit publish                               # emit witness-submission JSON for the current head
citadel tpm audit witness list                          # manage witness receipts
citadel tpm audit streams list                          # multi-stream management
citadel tpm audit key ...                               # master KEK for envelope-encrypted payloads
```

The implementation lives in the standalone `secure-log` workspace (a sibling repo, reused across projects) and is re-exported as `tpm_core::secure_log`; `tpm audit` and the `tpmd` witness endpoint persist to a `secure-log-sqlite` store alongside the metadata database.

### Measured Merkle Anchor (MMA)

MMA extends the TPM's chain of trust past the kernel: applications and artifacts are measured, the measurements branch into a Merkle tree, and the root is checkpoint-signed by a TPM-backed identity and anchored into a PCR. Citadel can also measure *itself* (`measure enroll`), so a quote attests which agent produced the anchor.

```bash
citadel tpm measure file /usr/bin/app --kind binary       # measure an artifact into the MMA stream
citadel tpm measure enroll --pcr 14 [--verify-ima]         # self-enroll Citadel's own binary (IMA-corroborated)
citadel tpm measure checkpoint [--extend-pcr 14]           # seal pending measurements into a Merkle segment, anchor the root
citadel tpm measure sign --identity anchor 1               # TPM-sign the segment's root (the anchoring key)
citadel tpm measure verify 1                               # verify a measurement is included under a signed root
citadel tpm measure rollback-check                         # detect anchor-counter truncation
```

#### Upgrading without re-keying (the upgrade ceremony)

A measurement is blind to intent: a legitimate upgrade and a tamper are the same observable event — a previously-unseen measurement. Only an **authorization** distinguishes them. So an MMA signing key can be bound to an offline **authority** (TPM2_PolicyAuthorize) rather than to one frozen PCR state: it signs under *any* state the authority approves, and an upgrade is a new approval — not a key ceremony. Approvals land in the witnessed MMA log, so every authorized state change is public and attributable; an unapproved state is exactly the one with **no witnessed approval**, and the key refuses to sign it.

```bash
# One-time setup: an offline approver, and a signing key bound to it.
citadel tpm identity init release --authority                          # hold this key offline (HSM / air-gapped / quorum)
citadel tpm identity init anchor --authorized-by release --pcr-bind 14

# Each release: build, deploy, then authorize the new measured state.
citadel tpm measure enroll --pcr 14 --verify-ima                       # the new binary's measurement enters the MMA
citadel tpm policy approve --authority release --pcr 14                # authority signs the new state → witnessed in the log
citadel tpm measure checkpoint --extend-pcr 14
citadel tpm measure sign --identity anchor 1                           # the SAME key signs — no re-key across the upgrade
```

The TPM signing key never changes across upgrades; the MMA log, anti-rollback counter, and checkpoint chain stay continuous, and `citadel tpm attest verify` surfaces the approving authority and whether the signing state was logged-approved. Because a compromised authority makes attacks indistinguishable from upgrades, keep it offline and prefer M-of-N quorum with reproducible builds. See [`docs/design/mma-upgrade.md`](docs/design/mma-upgrade.md) for the full threat model.

### Maintenance

```bash
citadel tpm repair scan
citadel tpm repair plan
citadel tpm repair apply
citadel tpm gc plan
citadel tpm gc apply
citadel tpm log show [--object path] [--action filter] [--limit 50]
```

### Recovery

```bash
citadel tpm recover list
citadel tpm recover show tpm-cleared
```

Playbooks: `tpm-cleared`, `handle-mismatch`, `profile-drift`, `boot-change`, `metadata-corruption`, `key-rotation`.

### Education

```bash
citadel tpm explain pcr
citadel tpm template list
citadel tpm template show ci-signer
```

Topics: `pcr`, `policy`, `hierarchy`, `key`, `seal`, `attestation`, `nv`, `ek`, `ak`, `handle`, `session`, `dictionary-attack`.

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (shorthand for `--format json`) |
| `--format text\|json\|yaml` | Output format |
| `--backend auto\|mock\|tpm12\|device\|vtpm` | TPM backend |
| `--store-path <path>` | Metadata store location |
| `--plan` | Dry-run mode — show what would happen |
| `--verbose` | Debug logging |

Environment variables: `TPM_STORE_PATH`, `TPM_BACKEND`, `TPM_VTPM_COMPONENT`.

## TUI

Running `citadel` with no arguments in a terminal launches the interactive TUI.

| Key | Action |
|-----|--------|
| `1`-`4` | Switch view (dashboard, objects, policies, audit) |
| `Tab` | Cycle views |
| `j`/`k` | Navigate |
| `Enter` | Detail view |
| `n` | Create new key |
| `d` | Delete selected object |
| `r` | Refresh |
| `q`/`Esc` | Back/quit |

The dashboard shows health score, backend status, object counts, and the active profile.

## Daemon

`tpmd` is an HTTP daemon that exposes TPM operations as a REST API with authentication, approval workflows, and audit logging.

```bash
tpmd                              # start on 127.0.0.1:7701 (mock backend)
TPMD_LISTEN=0.0.0.0:8443 tpmd    # custom address
TPMD_API_KEY=secret tpmd          # require X-API-Key header
TPMD_TLS_CERT=cert.pem TPMD_TLS_KEY=key.pem tpmd  # TLS with an on-disk key
```

By default `tpmd` runs the software (mock) backend. Build with `--features
vtpm` and set `TPMD_BACKEND=vtpm` (+ `TPM_VTPM_COMPONENT`) to run on the real
libtpms-WASM vTPM — required for real signing, including the TPM-held TLS key
below. vTPM state persists at `TPMD_VTPM_STATE` (default `<store>.tpmstate`).

```bash
TPMD_BACKEND=vtpm TPM_VTPM_COMPONENT=/path/to/tpm.component.wasm tpmd
```

#### TLS with a TPM-held server key

The daemon can terminate TLS using a TPM-resident key instead of a private
key file — the key never exists on disk, and the TLS handshake is signed
inside the TPM. Point it at a citadel **identity** whose key is TPM-backed:

```bash
TPMD_TLS_IDENTITY=tpmd-tls tpmd        # server key = identity 'tpmd-tls', signed in the TPM
```

The certificate is taken from the identity's stored `certificate_pem`, or
from `TPMD_TLS_CERT` if set; its public key must match the identity's TPM
key. `TPMD_TLS_IDENTITY` takes precedence over the on-disk `TPMD_TLS_KEY`
path. This path requires an ECDSA-capable backend (the vTPM or hardware TPM)
since the handshake is signed by the TPM; the software mock cannot terminate
a live TLS handshake.

### API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/status | Backend info |
| GET | /v1/health | Health posture and score |
| GET | /v1/keys | List keys |
| POST | /v1/keys | Create key `{"path":"..."}` |
| GET | /v1/keys/:path | Key details |
| POST | /v1/sign/:path | Sign data `{"data_hex":"..."}` |
| POST | /v1/delete/:path | Delete object |
| GET | /v1/objects | List all objects |
| GET | /v1/policies | List policies |
| POST | /v1/policies | Create policy |
| GET | /v1/secrets | List sealed secrets |
| GET | /v1/audit | Audit log |
| POST | /v1/audit/witness | Submit a secure-log witness co-signature |
| GET | /v1/approvals | List approval requests |
| POST | /v1/approvals | Request approval |
| POST | /v1/approvals/:id/approve | Approve |
| POST | /v1/approvals/:id/deny | Deny |

Approvals are persisted to the SQLite store and survive daemon restarts.

## Diagnostics

Errors use stable codes and follow a Rust-compiler-inspired format:

```
error[TPM0004]: object not found: signing/missing

  causes:
    - no object with path 'signing/missing' exists in the workspace

  path  signing/missing

  next steps:
    1. run `citadel tpm object list` to see all objects
    2. run `citadel tpm key list` to see available keys
```

27 diagnostic codes covering transport, objects, store, backend, policy, NV, attestation, repair, and internal errors.

## Architecture

```
citadel tpm (CLI + TUI)          tpmd (HTTP daemon)       tpm-wasi (WASM CLI)
       |                        |                        |
       v                        v                        v
                    tpm-core (shared library)
                         |
            +------------+------------+
            |            |            |
         Store       Backend     Diagnostics
      (trait-based)   (trait)    (27 codes)
            |            |
       +---------+  +----+----+----+
       |         |  |    |    |    |
    SQLite   Memory Mock  HW   vtpm
   (native)  (WASM)     (esapi)   (libtpms)
```

The store is abstracted behind a `StoreBackend` trait. Native builds use SQLite; WASM builds use an in-memory backend. `tpm-core` compiles to `wasm32-wasip2`:

```bash
cargo build -p tpm-core --target wasm32-wasip2 --no-default-features
```

The tamper-evident secure log lives outside this tree in the standalone `secure-log` workspace (sibling repo), so it can be reused by other projects. `tpm-core` path-depends on its `secure-log` / `secure-log-sqlite` crates and re-exports them as `tpm_core::secure_log`; a `TpmCheckpointSigner` adapts the TPM backend and identity store to the crate's `CheckpointSigner` trait for checkpoint signing.

## Development

```bash
cargo build --workspace                    # build all
cargo test --workspace                     # the full workspace suite (mesh, control plane, MSS, SPIFFE, observability, tpm)
cargo build --features vtpm                # with vTPM backend
cargo build --features tpm-hw              # with hardware TPM

# Run vTPM smoke tests against real libtpms
TPM_VTPM_COMPONENT=path/to/tpm-ephemeral.component.wasm \
  cargo test --features vtpm --test vtpm_smoke

# Build WASI CLI
cargo build -p tpm-wasi --target wasm32-wasip2
wasmtime run target/wasm32-wasip2/debug/tpm-wasi.wasm status
```

## License

Apache-2.0
