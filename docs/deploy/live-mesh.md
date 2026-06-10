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
- **Rich measured boot** (the firmware TCG event log) works in a QEMU+OVMF+swtpm
  VM: an agent there stages **109 real firmware events** (vs 0 on macOS/plain
  Lima). Validated end to end — see [Measured boot](#measured-boot-in-a-vm--working).
  The only thing not yet demonstrated is *three* such VMs running concurrently
  (an HVF-foreground/orchestration constraint, not a Citadel one).

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

## Measured boot in a VM — WORKING

A real firmware event log requires the guest to boot **UEFI (OVMF) with a TPM
attached**. Lima/vz on Apple Silicon cannot attach a TPM, so this needs
hand-rolled QEMU + swtpm. **Validated end to end** (2026-06): an agent on a
QEMU+swtpm VM stages **109 real firmware events** (vs 0 on macOS / plain Lima).

Result captured (`/dev/tpm0` + `/dev/tpmrm0` present, real PCRs, an
11 KB `Spec ID Event03` TCG2 log):

```
$ cat agent.log
staged measured state: 109 firmware events, 1 IMA entries
$ cat sys.txt
PCR0=F39F09C767B0...  PCR7=127C18EBA230...  PCR14=306F9D8B94F1...
```

### Three gotchas that make or break it

1. **HVF must run in the foreground.** `qemu -accel hvf` parks its vCPU at 0% CPU
   if the process is detached/backgrounded (no firmware output, never boots). Run
   QEMU in the foreground; use the **capture model** below so it still does useful
   work unattended.
2. **swtpm wiring:** point QEMU's chardev at swtpm's **`--ctrl`** socket (not a
   `--server` data socket), and **manufacture the state first** with `swtpm_setup
   --tpm2`. Wrong wiring/uninitialised state → OVMF's Tcg2 measured boot hangs
   (boots fine without a TPM, hangs with a misconfigured one).
3. **Capture model, not persistent SSH.** cloud-init does the work on boot and
   powers off — avoids needing networking/SSH into the guest.

### Working recipe (one node, capture model)

```bash
W=~/.cache/citadel-qemu              # OVMF code.fd + vars, the agent binary, a 9p share dir
swtpm_setup --tpm2 --tpm-state $W/ftpm1 --overwrite
swtpm socket --tpm2 --tpmstate dir=$W/ftpm1 \
  --ctrl type=unixio,path=$W/ftpm1.sock --flags startup-clear &     # NOTE: --ctrl
# cloud-init (NoCloud seed) runcmd: mount the 9p share, copy
#   /sys/kernel/security/tpm0/binary_bios_measurements + PCRs, run the agent
#   (root, so it reads securityfs), write agent.log, then `poweroff`.
timeout 220 qemu-system-aarch64 \
  -machine virt,accel=hvf -cpu host -m 2560 -smp 2 -display none \
  -serial file:$W/console.log \
  -drive if=pflash,format=raw,readonly=on,file=$W/code.fd \
  -drive if=pflash,format=raw,file=$W/vars.fd \
  -chardev socket,id=chrtpm,path=$W/ftpm1.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0 \
  -drive if=virtio,format=qcow2,file=$W/node.qcow2 \
  -drive if=virtio,format=raw,file=$W/seed.iso \
  -fsdev local,id=fsdev0,path=$W/share,security_model=mapped-xattr \
  -device virtio-9p-pci,fsdev=fsdev0,mount_tag=host \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0
# QEMU exits rc=0 when cloud-init powers off; read $W/share/{eventlog.bin,agent.log,sys.txt}.
```

(`scripts/capture-eventlog-aarch64.sh` is the original capture recipe; its swtpm
chardev points at the `--server` socket, which is why a naive copy hangs — use
`--ctrl` as above.)

**Remaining for a full measured-boot *mesh*:** running **three** such VMs
*persistently and concurrently* with cross-node networking. The blocker is purely
environmental — HVF needs foreground, so three persistent VMs can't be launched
through a backgrounding harness; on a normal terminal (or with systemd units on
real hardware) each runs in its own foreground/service. The Citadel pieces are all
proven: the agent ingests real measured boot (here), and the mesh fully converges
over real HTTP ([above](#convergence-note-important-operational-finding)).

## What this validates vs. the in-process harness

The harness (`citadel-mesh::harness`) simulates the mesh deterministically
in-process. Running real agents additionally exercises: real HTTP/TCP transport,
process isolation, real per-node TPM backends, and (on Linux) real `securityfs`
measured state — and surfaced the startup-ordering convergence finding above,
which the synchronous harness hides.
