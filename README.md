# Citadel

A stateful, operator-friendly TPM platform. Replaces low-level `tpm2-tools` with a resource-oriented interface built around named objects, declarative policies, explainable errors, and structured output.

## Why

The existing TPM toolchain is powerful but hostile. Common workflows require explicit context file management, manual command sequencing, opaque error codes, and deep spec knowledge. This tool makes the TPM feel like a managed object store:

- **Named objects** instead of context files and raw handles
- **Workflow collapsing** — `tpm key create` does the right create/load/persist sequence
- **Explainable diagnostics** — cause chains, context, actionable next steps
- **Structured output** — `--json` or `--format yaml` on every command
- **Declarative policies** — YAML policy files compiled and tested before use
- **Auto-detection** — finds hardware TPM, vTPM, or falls back to mock

## Install

```bash
bash install.sh
```

This builds a release binary with vTPM support, installs it to `~/.local/bin/tpm`, installs the libtpms WASM component to `~/.local/share/tpm/` (from a local libtpms-wasm build if present, otherwise downloaded from the [libtpms-wasm](https://github.com/tegmentum/libtpms-wasm) release), and sets up shell completions.

### From source (manual)

```bash
cargo build --release --features vtpm
cp target/release/tpm ~/.local/bin/
```

### Shell completions

```bash
tpm completions zsh  > ~/.zsh/completions/_tpm
tpm completions bash > ~/.local/share/bash-completion/completions/tpm
tpm completions fish > ~/.config/fish/completions/tpm.fish
```

## Quick start

```bash
tpm init
tpm key create signing/release
tpm key sign signing/release --input artifact.tar.gz
tpm key list
tpm --json status
tpm                             # launches TUI
```

## Backends

The `--backend` flag (or `TPM_BACKEND` env var) selects the TPM backend. Default is `auto`.

| Backend | Description |
|---------|-------------|
| `auto` | Probe in order: hardware TPM, vTPM, mock (default) |
| `device` | Hardware TPM at `/dev/tpmrm0` (requires `--features tpm-hw`) |
| `vtpm` | In-process libtpms via WASM/wasmtime (requires `--features vtpm`) |
| `mock` | Deterministic in-memory mock for development |

Auto-detection checks for `/dev/tpmrm0` first, then looks for the vTPM component at `~/.local/share/tpm/tpm-ephemeral.component.wasm`, and falls back to mock if neither is found.

The vTPM persists its state alongside the metadata store at `<store>.tpmstate`, so keys, NV, and saved PCRs (0–15) survive across separate `tpm` invocations — signing, sealing, attestation, and seal-to-attested-set work end-to-end on the virtual TPM, not just the mock. Permanent state restores on startup; volatile state (PCRs/sessions) is checkpointed with `Shutdown(STATE)` and resumed with `Startup(STATE)`. Note that PCRs 16–23 are resettable and not in the save set, so use a PCR in 0–15 when you need a measurement anchor to persist across invocations.

## Commands

### Workspace

```bash
tpm init [--profile <name>]        # initialize workspace
tpm status                         # backend + workspace + health score
tpm doctor                         # diagnostic health checks
tpm capabilities                   # algorithms, PCR banks, limits
tpm debug --output bundle.json     # collect diagnostic bundle
tpm workspace info                 # workspace summary
tpm workspace export --output f    # export metadata to JSON
tpm workspace import --input f     # import metadata from JSON
```

### Keys

```bash
tpm key create signing/release [--algorithm ecc-p256] [--policy boot-policy]
tpm key list [--json]
tpm key show signing/release
tpm key sign signing/release --input file.bin [--output sig.bin]
tpm key delete signing/release
tpm key export-pub signing/release [--export-for openssl|ssh|cosign|pkcs11]
tpm key rotate signing/release
```

### Secrets

```bash
tpm secret seal db/password --input secret.txt [--policy boot-seal]
tpm secret unseal db/password [--output recovered.txt]
tpm secret list
```

### Remote attestation

```bash
tpm attest ak-create attest/main
tpm attest quote --ak attest/main --pcr 0,7,11 --nonce challenge --output quote.json
tpm attest verify --quote quote.json --nonce challenge
```

### NV storage

```bash
tpm nv define config/build-id --size 64
tpm nv write config/build-id --input data.txt
tpm nv read config/build-id [--output data.txt]
tpm nv list
tpm nv delete config/build-id
```

### PCR operations

```bash
tpm pcr show --bank sha256 --index 0,7,11
tpm pcr baseline save clean-boot --index 0,7,11
tpm pcr baseline diff clean-boot
tpm pcr baseline list
```

### Policies

```bash
tpm policy create boot-policy --pcr 7,11 [--password]
tpm policy compile policy.yaml
tpm policy test boot-policy
tpm policy explain boot-policy
tpm policy show boot-policy
tpm policy list
tpm policy delete boot-policy
tpm policy approve --authority release --pcr 14   # approve the live measured state for PolicyAuthorize-bound keys
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
tpm object list
tpm object tree
tpm object dependents signing/key
tpm object rename old/name new/name
tpm object retire signing/old
tpm object activate signing/old
```

### Profiles

Profiles are mutable defaults applied to new operations. They can include constraints that enforce algorithm restrictions, path prefixes, and approval requirements.

```bash
tpm profile list
tpm profile show [name]
tpm profile set ci-signer
```

### Identities

An identity bundles a backing key, an intended usage, an optional policy, and certificate metadata into one named object. Audit checkpoint signing references identities by name.

```bash
tpm identity init auditor [--usage code-signing] [--algorithm ecc-p256] [--policy boot-policy]
tpm identity show auditor
tpm identity list
tpm identity rotate auditor
tpm identity delete auditor
```

A signing key can be bound to a measured state so the TPM itself refuses to sign unless the host matches it:

```bash
tpm identity init anchor --pcr-bind 14                       # frozen: signs only while PCR 14 matches creation time
tpm identity init release --authority                        # an offline PolicyAuthorize approver (the upgrade root)
tpm identity init anchor --authorized-by release --pcr-bind 14   # upgradable: signs any state `release` has approved
```

`--pcr-bind` freezes the key to one PCR state (an upgrade would brick it). `--authorized-by` binds it to an authority key instead (TPM2_PolicyAuthorize): the same key keeps signing across upgrades, gated on a witnessed approval — see [Measured Merkle Anchor](#measured-merkle-anchor-mma) below.

### Secure audit log

`tpm audit` is a tamper-evident secure log: entries are hash-chained, sealed into Merkle-rooted segments, and checkpoint-signed by a TPM-backed identity. An anti-rollback head file guards against truncation, payloads can be envelope-encrypted under a master KEK, and segment heads can be co-signed by an external witness. Multiple independent streams (each with a confidentiality tier) are supported.

```bash
tpm audit append --event user.login --payload "session opened"   # append a hash-chained entry
tpm audit head                                  # highest seqno for a stream
tpm audit show 1                                # read an entry by seqno
tpm audit chain verify                          # verify the hash chain
tpm audit segments close                        # seal the open window into a Merkle segment
tpm audit sign --identity auditor 1             # TPM-sign a closed segment's checkpoint
tpm audit verify                                # verify the checkpoint chain from genesis to head
tpm audit prove 1                               # build a Merkle inclusion proof for an entry
tpm audit rollback                              # check the anti-rollback head file vs the database
tpm audit publish                               # emit witness-submission JSON for the current head
tpm audit witness list                          # manage witness receipts
tpm audit streams list                          # multi-stream management
tpm audit key ...                               # master KEK for envelope-encrypted payloads
```

The implementation lives in the standalone `secure-log` workspace (a sibling repo, reused across projects) and is re-exported as `tpm_core::secure_log`; `tpm audit` and the `tpmd` witness endpoint persist to a `secure-log-sqlite` store alongside the metadata database.

### Measured Merkle Anchor (MMA)

MMA extends the TPM's chain of trust past the kernel: applications and artifacts are measured, the measurements branch into a Merkle tree, and the root is checkpoint-signed by a TPM-backed identity and anchored into a PCR. Citadel can also measure *itself* (`measure enroll`), so a quote attests which agent produced the anchor.

```bash
tpm measure file /usr/bin/app --kind binary       # measure an artifact into the MMA stream
tpm measure enroll --pcr 14 [--verify-ima]         # self-enroll Citadel's own binary (IMA-corroborated)
tpm measure checkpoint [--extend-pcr 14]           # seal pending measurements into a Merkle segment, anchor the root
tpm measure sign --identity anchor 1               # TPM-sign the segment's root (the anchoring key)
tpm measure verify 1                               # verify a measurement is included under a signed root
tpm measure rollback-check                         # detect anchor-counter truncation
```

#### Upgrading without re-keying (the upgrade ceremony)

A measurement is blind to intent: a legitimate upgrade and a tamper are the same observable event — a previously-unseen measurement. Only an **authorization** distinguishes them. So an MMA signing key can be bound to an offline **authority** (TPM2_PolicyAuthorize) rather than to one frozen PCR state: it signs under *any* state the authority approves, and an upgrade is a new approval — not a key ceremony. Approvals land in the witnessed MMA log, so every authorized state change is public and attributable; an unapproved state is exactly the one with **no witnessed approval**, and the key refuses to sign it.

```bash
# One-time setup: an offline approver, and a signing key bound to it.
tpm identity init release --authority                          # hold this key offline (HSM / air-gapped / quorum)
tpm identity init anchor --authorized-by release --pcr-bind 14

# Each release: build, deploy, then authorize the new measured state.
tpm measure enroll --pcr 14 --verify-ima                       # the new binary's measurement enters the MMA
tpm policy approve --authority release --pcr 14                # authority signs the new state → witnessed in the log
tpm measure checkpoint --extend-pcr 14
tpm measure sign --identity anchor 1                           # the SAME key signs — no re-key across the upgrade
```

The TPM signing key never changes across upgrades; the MMA log, anti-rollback counter, and checkpoint chain stay continuous, and `tpm attest verify` surfaces the approving authority and whether the signing state was logged-approved. Because a compromised authority makes attacks indistinguishable from upgrades, keep it offline and prefer M-of-N quorum with reproducible builds. See [`docs/design/mma-upgrade.md`](docs/design/mma-upgrade.md) for the full threat model.

### Maintenance

```bash
tpm repair scan
tpm repair plan
tpm repair apply
tpm gc plan
tpm gc apply
tpm log show [--object path] [--action filter] [--limit 50]
```

### Recovery

```bash
tpm recover list
tpm recover show tpm-cleared
```

Playbooks: `tpm-cleared`, `handle-mismatch`, `profile-drift`, `boot-change`, `metadata-corruption`, `key-rotation`.

### Education

```bash
tpm explain pcr
tpm template list
tpm template show ci-signer
```

Topics: `pcr`, `policy`, `hierarchy`, `key`, `seal`, `attestation`, `nv`, `ek`, `ak`, `handle`, `session`, `dictionary-attack`.

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (shorthand for `--format json`) |
| `--format text\|json\|yaml` | Output format |
| `--backend auto\|mock\|device\|vtpm` | TPM backend |
| `--store-path <path>` | Metadata store location |
| `--plan` | Dry-run mode — show what would happen |
| `--verbose` | Debug logging |

Environment variables: `TPM_STORE_PATH`, `TPM_BACKEND`, `TPM_VTPM_COMPONENT`.

## TUI

Running `tpm` with no arguments in a terminal launches the interactive TUI.

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
tpmd                              # start on 127.0.0.1:7701
TPMD_LISTEN=0.0.0.0:8443 tpmd    # custom address
TPMD_API_KEY=secret tpmd          # require X-API-Key header
TPMD_TLS_CERT=cert.pem TPMD_TLS_KEY=key.pem tpmd  # TLS
```

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
    1. run `tpm object list` to see all objects
    2. run `tpm key list` to see available keys
```

27 diagnostic codes covering transport, objects, store, backend, policy, NV, attestation, repair, and internal errors.

## Architecture

```
tpm (CLI + TUI)          tpmd (HTTP daemon)       tpm-wasi (WASM CLI)
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
cargo test --workspace                     # 171 tests
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
