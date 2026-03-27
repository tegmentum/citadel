# tpm

A stateful, operator-friendly TPM platform that transforms TPM usage from low-level command execution into a coherent, inspectable, and safe operational system.

## Overview

`tpm` replaces the fragmented TPM tooling ecosystem with a unified interface organized around **resources and workflows** rather than TPM command names. It introduces named objects, stored metadata, declarative policies, explainable errors, and structured output.

Two binaries:

- **`tpm`** -- CLI and TUI for operator interaction
- **`tpmd`** -- HTTP daemon exposing trust operations as an API

## Quick Start

```bash
# Build
cargo build --release

# Initialize workspace
tpm init

# Create a signing key
tpm key create signing/release

# Sign a file
tpm key sign signing/release --input artifact.tar.gz

# List everything
tpm object tree

# Launch the TUI
tpm
```

## Installation

### From source

```bash
git clone <repo>
cd tpm
cargo install --path .
```

### With hardware TPM support

Requires `tpm2-tss` development libraries.

```bash
# Debian/Ubuntu
apt install libtss2-dev

# Fedora
dnf install tpm2-tss-devel

# Build with hardware support
cargo install --path . --features tpm-hw
```

## Command Reference

### Workspace

```bash
tpm init [--profile <name>]       # Initialize workspace
tpm status                        # Backend and workspace summary with health score
tpm doctor                        # Diagnostic health checks
tpm capabilities                  # Show TPM capabilities and supported algorithms
tpm debug --output bundle.json    # Collect diagnostic bundle
tpm workspace info                # Workspace summary
tpm workspace export --output f   # Export metadata to JSON
tpm workspace import --input f    # Import metadata from JSON
```

### Keys

```bash
tpm key create signing/release [--algorithm ecc-p256] [--policy boot-policy]
tpm key list [--format json]
tpm key show signing/release
tpm key sign signing/release --input file.bin [--output sig.bin]
tpm key delete signing/release
tpm key export-pub signing/release [--export-for openssl|ssh|cosign|pkcs11]
tpm key rotate signing/release    # Create new key, archive old
```

### Secrets

```bash
tpm secret seal db/password --input secret.txt [--policy boot-policy]
tpm secret unseal db/password [--output recovered.txt]
tpm secret list
```

### NV Storage

```bash
tpm nv define config/build-id --size 64
tpm nv write config/build-id --input data.txt
tpm nv read config/build-id [--output data.txt]
tpm nv list
tpm nv delete config/build-id
```

### Remote Attestation

```bash
tpm attest ak-create attest/main
tpm attest quote --ak attest/main --pcr 0,7,11 --nonce challenge --output quote.json
tpm attest verify --quote quote.json --nonce challenge
```

### PCR Operations

```bash
tpm pcr show --bank sha256 --index 0,7,11
tpm pcr baseline save clean-boot --index 0,7,11
tpm pcr baseline diff clean-boot
tpm pcr baseline list
```

### Policies

```bash
tpm policy create boot-policy --pcr 7,11 [--password]
tpm policy compile policy.yaml     # Compile from declarative YAML
tpm policy test boot-policy        # Check satisfiability
tpm policy explain boot-policy     # Human-readable explanation
tpm policy show boot-policy
tpm policy list
tpm policy delete boot-policy
```

Policy YAML format:

```yaml
name: boot-integrity
description: Ensure expected boot state
requires:
  pcr:
    - index: 7
    - index: 11
  auth_value: true
```

### Objects

```bash
tpm object list                   # Tabular listing of all objects
tpm object tree                   # Tree view grouped by type
tpm object dependents signing/key # Show what depends on an object
tpm object rename old/name new/name
tpm object retire signing/old     # Mark inactive
tpm object activate signing/old   # Reactivate
```

### Profiles

```bash
tpm profile list
tpm profile show [name]
tpm profile set ci-signer
```

### Maintenance

```bash
tpm repair scan                   # Detect workspace issues
tpm repair plan                   # Preview fixes
tpm repair apply                  # Apply automatic repairs
tpm gc plan                       # Show GC candidates
tpm gc apply                      # Remove stale objects
tpm log show [--object path] [--action filter] [--limit 50]
```

### Recovery

```bash
tpm recover list                  # List recovery playbooks
tpm recover show tpm-cleared      # Step-by-step recovery guide
```

Available playbooks: `tpm-cleared`, `handle-mismatch`, `profile-drift`, `boot-change`, `metadata-corruption`, `key-rotation`.

### Education

```bash
tpm explain pcr                   # Learn about TPM concepts
tpm template list                 # Browse configuration templates
tpm template show ci-signer       # Detailed template with example
```

Topics: `pcr`, `policy`, `hierarchy`, `key`, `seal`, `attestation`, `nv`, `ek`, `ak`, `handle`, `session`, `dictionary-attack`.

### Simulator

```bash
tpm simulator start               # Start swtpm process
tpm simulator stop
tpm simulator status
```

### Daemon

```bash
tpm daemon run [--listen 127.0.0.1:7701]
tpm daemon status
```

Or run directly:

```bash
TPMD_LISTEN=127.0.0.1:7701 tpmd
```

## Global Options

| Flag | Description |
|------|-------------|
| `--format text\|json\|yaml` | Output format (default: text) |
| `--backend mock\|device\|swtpm` | TPM backend (default: mock) |
| `--store-path <path>` | Metadata store location |
| `--plan` | Dry-run mode |
| `--verbose` | Debug logging |

Environment variables: `TPM_STORE_PATH`, `TPM_BACKEND`.

## TUI

Running `tpm` with no arguments in an interactive terminal launches the TUI.

| Key | Action |
|-----|--------|
| `1`-`4` | Switch view (dashboard, objects, policies, audit) |
| `Tab` | Cycle views |
| `j`/`k` | Navigate |
| `Enter` | Detail view |
| `n` | Create new key |
| `d` | Delete selected |
| `r` | Refresh |
| `q`/`Esc` | Back/quit |

## Daemon API

`tpmd` exposes a JSON API on port 7701.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/status | Backend info |
| GET | /v1/health | Health posture and score |
| GET | /v1/keys | List keys |
| POST | /v1/keys | Create key `{"path":"...","algorithm":"..."}` |
| GET | /v1/keys/:path | Key details |
| POST | /v1/sign/:path | Sign data `{"data_hex":"..."}` |
| POST | /v1/delete/:path | Delete object |
| GET | /v1/objects | List all objects |
| GET | /v1/policies | List policies |
| POST | /v1/policies | Create policy |
| GET | /v1/secrets | List sealed secrets |
| GET | /v1/audit | Audit log |

Authentication: set `TPMD_API_KEY` env var; requests require `X-API-Key` header.

## Architecture

```
tpm (CLI + TUI)          tpmd (HTTP daemon)
       |                        |
       v                        v
  tpm-core (shared library)
       |
  +---------+-----------+
  |         |           |
Store    Backend    Diagnostics
(SQLite) (trait)    (27 codes)
  |         |
  |    +----+----+
  |    |    |    |
  |  Mock  HW  swtpm
  |       (tss-esapi)
  v
 objects, policies, profiles,
 audit log, NV indices,
 PCR baselines
```

## Diagnostics

Errors follow a Rust-compiler-inspired format with stable codes:

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

## Development

```bash
# Build
cargo build --workspace

# Test (38 tests)
cargo test --workspace

# Run with mock backend (default)
cargo run -- status

# Run with hardware TPM
cargo run --features tpm-hw -- --backend device status

# Run with swtpm simulator
tpm simulator start
cargo run --features tpm-hw -- --backend swtpm status
```

## License

Apache-2.0
