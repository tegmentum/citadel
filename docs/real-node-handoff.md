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

## Task 2 — agent ships its real logs  (small code, then run on the node)
The mesh paths exist and are tested with *staged* logs; what's missing is the
agent reading the node's actual `/sys` on startup. Two readers:

* **C1 (IMA):** read `/sys/kernel/security/ima/ascii_runtime_measurements` →
  `Node::stage_ima(...)` so the agent's evidence carries its real runtime list
  (verifiers then appraise it via the witness quorum — already wired).
* **B1 (firmware):** read `/sys/kernel/security/tpm0/binary_bios_measurements`,
  return it from a `/sys`-backed `read_event_log`, and feed the
  `MeasurementEvent` stream into `logship::append_event` (fills log-ship §6).

I can implement both (Linux-gated, ~small); they then need **node validation**:
run two agents on the node (or two nodes), confirm one distrusts the other when
a denylisted file is in the real IMA list, and that the firmware log ships +
replays. Say the word and I'll write them for you to run.

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
