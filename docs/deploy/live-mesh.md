# Running a live Citadel mesh (networked agents) — deploy notes

**Status:** validated on macOS host + an aarch64 Linux VM (2026-06).

This captures what it takes to run Citadel as **real networked nodes** (separate
`citadel-agent` processes gossiping over HTTP), what was validated, and the one
piece that needs a dedicated infra session (rich measured boot in a VM).

## TL;DR — what's proven

- A **3-node mesh of real OS processes** gossiping over HTTP (`POST /v1/gossip`)
  **fully converges to all-`Trusted`** in ~8s. Not the in-process harness — three
  separate `citadel-agent` processes over real TCP.
- The agent **builds + runs on real aarch64 Linux** and stages **real measured
  evidence** from `securityfs` (IMA), where macOS stages none.
- **Rich measured boot** (the firmware TCG event log) needs a VM with a real vTPM
  (QEMU + OVMF + swtpm); plain Lima/vz can't attach one. The recipe exists
  (`scripts/capture-eventlog-aarch64.sh`); adapting it to run the agent
  persistently is the open task (see [Measured boot](#measured-boot-in-a-vm)).

## Run a 3-node mesh (host or VM)

`citadel-agent` runs one node per process, configured by env (see its
`main.rs`). Peers are addressed by seed → derived id.

```bash
cargo build --release -p citadel-agent
BIN=./target/release/citadel-agent

# Start ALL nodes together (see the convergence note below).
CITADEL_SEED=1 CITADEL_LISTEN=127.0.0.1:7801 \
  CITADEL_PEERS='[[2,"http://127.0.0.1:7802"],[3,"http://127.0.0.1:7803"]]' $BIN &
CITADEL_SEED=2 CITADEL_LISTEN=127.0.0.1:7802 \
  CITADEL_PEERS='[[1,"http://127.0.0.1:7801"],[3,"http://127.0.0.1:7803"]]' $BIN &
CITADEL_SEED=3 CITADEL_LISTEN=127.0.0.1:7803 \
  CITADEL_PEERS='[[1,"http://127.0.0.1:7801"],[2,"http://127.0.0.1:7802"]]' $BIN &

# Watch convergence (each node should see all peers `trusted`):
curl -s http://127.0.0.1:7801/v1/mesh/status   # [{...,"trust":"trusted"}, ...]
```

The agent serves only `POST /v1/gossip` (peer gossip) and `GET /v1/mesh/status`
(this node's view of the mesh).

### Convergence note (important operational finding)

Trust convergence is **sensitive to startup ordering**. If nodes start
*sequentially* with gaps, a late-joining node misses the earlier nodes' initial
evidence broadcast and never attests them — they stay `unknown` to it (observed:
a stable matrix where node X trusts node Y iff Y started at-or-after X). Starting
all nodes **together** converges fully in seconds.

This is an operational gotcha, not a trust defect — but it points at a real
**improvement**: the agent should re-advertise its evidence under anti-entropy
(like it does for reference manifests, `manifest_advert_interval`) so a
late-joiner can attest peers that came up before it. Until then: start nodes
together, or restart a late node's peers, or (deployment) seed evidence via the
node's `apply_reference_manifest` / re-attestation path.

## TPM backends & what each provides

`CITADEL_TPM_BACKEND` selects the per-node TPM (see `make_backend`). Evidence has
two independent parts: the **firmware event log** (`/sys/.../tpm0/binary_bios_measurements`,
from UEFI measured boot — needs a TPM device) and the **IMA list**
(`/sys/.../ima/ascii_runtime_measurements`, from the kernel — needs `ima_policy`).

| Backend | Build | Firmware log | IMA | Notes |
|---|---|---|---|---|
| `mock` (default) | none | — | from `/sys` if present | dev; deterministic quotes |
| `vtpm` | `--features vtpm` + `TPM_VTPM_COMPONENT` | — | from `/sys` | in-process libtpms; no measured boot |
| `tcti` | `--features tpm-hw` + `CITADEL_TPM_TCTI` | ✅ (with a UEFI+swtpm boot) | from `/sys` | real TPM 2.0 protocol to a device/swtpm |

Observed measured evidence by host:
- **macOS host**: 0 firmware events, 0 IMA — no `securityfs`. Mesh still converges
  (trust survives probation on clean attestation without rich evidence).
- **Plain Lima/vz Linux VM**: 0 firmware events (no vTPM attached), **1 IMA entry**
  (`boot_aggregate`; add `ima_policy=tcb` to the kernel cmdline for a rich list).
- **QEMU + OVMF + swtpm VM**: real firmware event log + PCRs (the measured-boot
  path) — see below.

## Measured boot in a VM

A real firmware event log requires the guest to boot **UEFI (OVMF) with a TPM
attached**. Lima/vz on Apple Silicon cannot attach a TPM, so this needs
hand-rolled QEMU. The project already does exactly this for fixture capture:

- `scripts/capture-eventlog-aarch64.sh` — `qemu-system-aarch64 -machine virt
  -accel hvf` + arm64 OVMF (two 64 MiB pflash images) + `swtpm` as
  `-tpmdev emulator … -device tpm-tis-device`, booting a cloud image whose
  cloud-init copies out `/sys/kernel/security/tpm0/binary_bios_measurements` and
  the live SHA-256 PCRs. Prereqs (`brew install qemu swtpm`, arm64 OVMF) are
  present on this machine.

**Open task:** adapt that recipe to boot a *persistent* VM that runs
`citadel-agent` (instead of capture-and-shutdown), ×3, with cross-node networking
(QEMU user-net `hostfwd` routed via the host, or `socket_vmnet` for VM-to-VM).
An attempt this session reached the QEMU+swtpm launch but the persistent guest
hung at firmware (silent boot, no SSH) — a console/cloud-init/image-compat issue
that needs iterative serial-console debugging. The capture script boots fine, so
the recipe is sound; the persistent-agent adaptation is the gap. Budget a focused
session for it.

## What this validates vs. the in-process harness

The harness (`citadel-mesh::harness`) simulates the mesh deterministically
in-process. Running real agents additionally exercises: real HTTP/TCP transport,
process isolation, real per-node TPM backends, and (on Linux) real `securityfs`
measured state — and surfaced the startup-ordering convergence finding above,
which the synchronous harness hides.
