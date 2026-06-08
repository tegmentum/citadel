# Citadel — real-node handoff

The work that can only run on a real Linux **node** — it needs a TPM, `securityfs`
(`/sys/kernel/security/...`), and (for the agent tasks) the node's own measured
state. The in-process harness and the QEMU lab can't substitute for these.

Ordered by "runnable right now" → "needs code first". Companion:
`docs/linux-handoff.md` (build/CI/toolchain), `docs/a1-capture-handoff.md` (QEMU lab).

## Prereqs on the node
- A TPM 2.0 (hardware/fTPM, or a TPM-equipped VM) with measured boot — check:
  `ls -l /sys/kernel/security/tpm0/binary_bios_measurements`
- For a *full* IMA list, boot with `ima_policy=tcb` (else only `boot_aggregate`):
  add it to the kernel cmdline (GRUB) and reboot, or it's already on.
- Rust **1.96** + the system deps from `docs/linux-handoff.md`.
- `sudo` (securityfs is root-readable).

---

## Task 1 — capture the node's REAL firmware log + IMA list  (runnable now, no code)
This is the broadest parser test available: real **vendor** firmware (not OVMF)
and the node's own runtime list. It closes A1 breadth and the C1 corpus on real
hardware.

> **Status:** done in a VM as far as a VM can go. A TPM-equipped QEMU guest
> (swtpm = TPM 2.0, root `/sys`) covers the prereqs, so the corpus now has two
> firmwares — `ubuntu-24.04-ovmf-amd64` (OVMF/UEFI) and `seabios-q35-tpm2-amd64`
> (SeaBIOS, adds `EV_EVENT_TAG`) — plus the `ubuntu-24.04-tcb-amd64` IMA list,
> all replaying/parsing green. What a VM *can't* give is real **vendor** firmware
> (Dell/HP/Lenovo UEFI, fTPM): run `sudo scripts/capture-node.sh` on actual
> bare metal to surface vendor `EV_*` quirks. (This dev box is a TPM **1.2** host
> with password `sudo`, so it can't — it has no `pcr-sha256` bank and a 0-byte
> firmware log.)

```sh
sudo scripts/capture-node.sh          # NAME=<label> to override the hostname
```
It drops `<host>.bin`+`<host>.sha256` into `tests/fixtures/eventlog/` and
`<host>.ascii` into `tests/fixtures/ima/`, then runs `eventlog_corpus` +
`ima_corpus`.

**Success:** both tests pass — the firmware log replays to the live PCRs and
every IMA line parses. Commit the new fixtures.
**If a test fails:** that's a real firmware/kernel wart (a vendor `EV_*` quirk,
an unhandled IMA template). Send the failing fixture + the test output; the fix
goes in `tpm_core::eventlog::parse_tcg` or `tpm_core::ima` with a regression test
built from the real bytes — same loop that hardened A1/A3.

> Bare-metal firmware is the most likely place to surface new `parse_tcg` cases
> (vendor `EV_EVENT_TAG`s, SHA-1-only legacy logs, padding). That's the point.

---

## Task 2 — agent ships its real logs  ✅ (implemented; needs node validation)
**Done.** The agent now reads the node's own `/sys` on startup and stages both
logs into its evidence:

* **`tpm_core::sys`** — `read_firmware_event_log()` /
  `read_ima_runtime_list()` read securityfs (paths overridable via
  `CITADEL_FIRMWARE_EVENT_LOG` / `CITADEL_IMA_RUNTIME_LIST` — point them at a
  captured fixture to dry-run without a live `/sys`). Absent/empty → `None`.
* **C1 (IMA):** `citadel-agent` calls `Node::stage_ima` (ships the list in
  evidence) + `Node::ingest_own_ima` (preserves it in the LtHash log).
* **B1 (firmware):** new `Node::stage_event_log` (ships the raw log in evidence
  and binds this node's own `pcr_bound` app measurements against it) +
  `Node::ingest_own_event_log` (feeds each `MeasurementEvent` into the LtHash
  log). The agent wires both in `stage_node_logs` at startup.

Unit + integration tests cover the readers (against the committed corpus), the
ingest, and the staged-log binding; `crates/citadel-mesh/tests/firmware_shipping.rs`.

**Remaining — node validation** (needs a real/VM node, not just CI): run two
agents, confirm one distrusts the other when a denylisted file is in the *real*
IMA list, and that the firmware log ships + replays against the quote. The
`CITADEL_*` env overrides let you stage a captured corpus into a running agent
to exercise the path end-to-end before bare metal.

---

## Task 3 — run the agent against the node's real TPM  (code + run)
Today `citadel-agent::main::make_backend` returns `MockBackend` (the demo).
On the node, wire a real backend so the agent attests + does mTLS with a
hardware-held key:
* **hardware TPM:** a `/dev/tpm0` backend (the `tpm-hw` path); or
* **swtpm:** `SwtpmManager` + a socket-driven backend.

Then run the existing flows against it on the node:
```sh
# with a real component/backend available:
TPM_VTPM_COMPONENT=... cargo test -p vtpm-backend           # 10 real-TPM tests
TPM_VTPM_COMPONENT=... cargo test -p citadel-agent --test mtls_transport
```
and bring up two `citadel-agent` processes (see `crates/citadel-agent/src/main.rs`
env config) to watch real attestation + mTLS gossip between them.

---

## What to send back
- New fixtures that **pass** (commit them) — they become permanent corpus.
- Any **failing** fixture + the test output (real-data warts to harden).
- For Task 2/3: whether you want me to implement the `/sys` readers and the
  real-TPM backend wiring first (then you run), or a different split.
