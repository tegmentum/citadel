# Citadel — Linux workstation handoff

A single reference for picking up the project on a Linux box. The whole
software-reachable roadmap is done; what's left needs **real hardware / real
data / a build pipeline** that a Linux workstation provides and macOS couldn't.

Companion docs: `docs/design/attestation-roadmap.md` (full status, per-item
detail), `docs/a1-capture-handoff.md` (firmware event-log capture mechanics).

---

## Repos (all four have green CI, runnable via `act`)

| Repo | Role | CI job |
|---|---|---|
| `citadel` (this) | mesh + tpm-core + agent + tpm-tls | `build-test` (fmt, clippy `-D warnings`, build, test ×2 features) |
| `pkcs11-x509` | `x509-path` chain-to-anchor (A2) | `build-test` + `wasm-component` |
| `vtpm-wasm` | in-process vTPM host (wasmtime + libtpms) | `build-test` (with `tpm-wit` submodule) |
| `secure-log` | hash-chained log / Merkle / checkpoints | `build-test` (host crates; 7 wasm cdylibs build via cargo-component) |

The three sibling git-deps (`secure-log`, `vtpm-wasm`, `pkcs11-x509`) are
**public**, so a clean checkout fetches everything without credentials.

## Toolchain & build
- **Rust 1.96** (the CI container's stable). Match it: `rustup default stable && rustup update`.
  1.96 clippy is stricter than 1.93 (this is what CI enforces).
- System deps (Debian/Ubuntu): `build-essential cmake clang libclang-dev pkg-config libssl-dev libsqlite3-dev`
  (cmake/clang are for **aws-lc-rs**, pulled by rustls/tpm-tls/reqwest).
- Gates, per repo: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`. On `citadel` also `cargo test -p citadel-mesh --features x509-authority`.

## CI locally via `act`
```sh
act                       # runs the push workflow in a container
act -j build-test
```
`.actrc` in each repo pins the image and disables the docker-socket mount. On a
Linux box with native Docker the `--container-architecture`/`DOCKER_HOST`
overrides used on the Mac (colima) are unnecessary.

## The vTPM (gated tests)
TPM-backed tests **self-skip** unless `TPM_VTPM_COMPONENT` points at a built
vTPM component (a `*.component.wasm`). With it set, they sign for real:
```sh
TPM_VTPM_COMPONENT=/path/to/tpm.component.wasm cargo test -p vtpm-backend
TPM_VTPM_COMPONENT=...                          cargo test -p tpm-tls --test mtls_handshake
TPM_VTPM_COMPONENT=...                          cargo test -p citadel-agent --test mtls_transport
```
Note: mint/sign needs a **persisted** vTPM (state file); the ephemeral one
returns a non-signature fallback. The mTLS tests use `VtpmBackend::open(.., Some(state))`.

---

## What's left to do on Linux

### 1. Close C1 — real IMA corpus  (◑ software loop done)
The IMA parser + runtime policy + trust escalation + LtHash shipping + evidence
transport are all built and tested; they just need validation against a **real**
IMA list. A default cloud image emits only `boot_aggregate` — boot with an IMA
policy:
```sh
# on a box with IMA in the kernel (most distro kernels):
#   add `ima_policy=tcb` to the kernel cmdline (GRUB), reboot, then:
sudo cp /sys/kernel/security/ima/ascii_runtime_measurements \
        crates/tpm-core/tests/fixtures/ima/$(hostname).ascii
cargo test -p tpm-core --test ima_corpus -- --nocapture
```
The harness asserts every line parses (no unknown templates). A skipped line is
a real-kernel wart — send it over and I'll harden `tpm_core::ima` (same loop
that fixed the GRUB label-hashing in A3). Then C1 → ✅. Remaining after that: an
agent-side reader of `/sys/.../ascii_runtime_measurements` feeding
`Node::stage_ima` (so a deployed agent ships its real list).

### 2. Close the B1 firmware tail  (vTPM part done)
Ingest a *firmware* event log on bare metal and wire it into the LtHash log:
```sh
# the parser already consumes this directly:
cat /sys/kernel/security/tpm0/binary_bios_measurements   # -> tpm_core::eventlog::parse_tcg
```
Implement `read_event_log` on a hardware/`/sys` backend to return these bytes,
then feed the `MeasurementEvent` stream into `logship::append_event` (fills
log-shipping §6). Needs real UEFI hardware (or the firmware corpus from the A1
lab for parser breadth).

### 3. A1 corpus breadth (optional, easy)
Drop any real `/sys/.../binary_bios_measurements` + its
`/sys/class/tpm/tpm0/pcr-sha256/*` into `crates/tpm-core/tests/fixtures/eventlog/`
as `<name>.bin` + `<name>.sha256` (one `<pcr> <hex>` per line). The harness
validates it automatically. See `docs/a1-capture-handoff.md` for the QEMU+OVMF+swtpm
lab (`scripts/capture-eventlog.sh`).

### 4. Software doc-tails (no hardware; do anytime)
- **A2 tail:** parse the real `EV_EFI_VARIABLE_AUTHORITY` `EFI_SIGNATURE_DATA`
  wrapper (vs. a raw cert) + a real `as_of` clock. Needs the A1 authority blobs
  to test against.
- **A3 tail:** PE-COFF version-resource extraction from
  `EV_EFI_BOOT_SERVICES_APPLICATION` device paths (the GRUB/IPL cmdline path
  already covers the kernel).
- **B2:** point `citadel_mesh::rvp` at a real approved-build pipeline's
  measurements (issuing/signing/ingest is done); optionally expose it as a CLI.

### 5. Release hygiene
- **`x509-path` re-pin:** `crates/citadel-mesh/Cargo.toml` tracks
  `x509-path` on `branch = "main"` with a `TODO(release)` marker — pin to an
  audited `rev` before release.
- **E2 follow-ups (optional):** a real hardware-TPM backend behind
  `citadel-agent::main::make_backend`; dedupe `tpmd::tls` onto the `tpm-tls`
  crate.
- **secure-log wasm CI:** the host-crate CI is green; a `cargo component build`
  job is blocked on `secure-log-rpc-server`'s wit "target world" config.

---

## Gotchas learned this cycle (don't relearn them)
- **Rust 1.96 vs older local:** CI's clippy is stricter (e.g. `unnecessary_sort_by`,
  `is_multiple_of`). Always run clippy on the same stable the container uses.
- **`act` + colima (macOS only):** needs `DOCKER_HOST=unix://~/.colima/default/docker.sock`,
  `--container-architecture linux/arm64`, and `--container-daemon-socket -`.
  On Linux/native Docker none of this applies.
- **`cargo fmt --all` on wasm-component crates** fails on a clean checkout: their
  `mod bindings;` file is generated by cargo-component. Scope fmt to host crates
  (see secure-log's CI).
- **GRUB measures `"<label>: <payload>"` but hashes only `<payload>`** (sometimes
  with a trailing NUL) — `MeasurementEvent::measured_text` reconciles it; and
  GRUB measures the *whole* boot menu, so gate cmdline policy on the **booted**
  line only (`extract_kernel_cmdline`), not the recovery `menuentry`.
- **`-serial file:` silently doesn't capture** on the brew QEMU build (macOS) —
  use `-serial stdio`. Not an issue with distro QEMU.
