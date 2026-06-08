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
ingest, and the staged-log binding (`firmware_shipping.rs`), plus an end-to-end
**node-validation over the real HTTP transport**
(`crates/citadel-agent/tests/node_validation.rs`): real agent processes form a
mesh, the "bad" one stages real kernel IMA lines via the startup reader, and a
witness challenges → receives the shipped IMA log → distrusts it when it carries
a denylisted file (≈0.2 s). So the C1 distrust path is validated with real
sockets, not just the in-process harness.

**Remaining — bare-metal only:**
- *Firmware ships + replays against the quote.* Needs a backend whose quote
  matches the staged firmware log; the demo `MockBackend` synthesizes its own
  log, so a real captured firmware log won't replay against a mock quote — this
  lands with **Task 3** (real/vTPM backend).
- *Vendor firmware breadth* (Task 1) still wants real hardware.

The `CITADEL_FIRMWARE_EVENT_LOG` / `CITADEL_IMA_RUNTIME_LIST` overrides let you
stage a captured corpus into a deployed agent to exercise the readers on a real
node before then.

---

## Task 3 — run the agent against the node's real TPM  ◑ (wiring done; needs an equipped node to run)
**Done — the wiring.** `citadel-agent::make_backend` now selects the backend from
`CITADEL_TPM_BACKEND`, falling back to the mock (so the agent always starts):
* `mock` (default) — the in-process demo (plain HTTP).
* `tcti` (build `--features tpm-hw`) — a real TPM via tss-esapi. Covers **both**
  the handoff's options through one TCTI seam: `CITADEL_TPM_TCTI=device:/dev/tpmrm0`
  (hardware) or `swtpm:path=/run/swtpm.sock` / `swtpm:host=…,port=…` (swtpm).
* `vtpm` (build `--features vtpm`) — the in-process libtpms vTPM:
  `TPM_VTPM_COMPONENT=<built .component.wasm>` + `CITADEL_VTPM_STATE=<persisted file>`.

A real backend signs for real → mutual TLS (E2). Validated on this dev box: the
mock default + the `vtpm`/`tcti` selectors compile, the fallback path works at
runtime, and the agent tolerates a real securityfs `Permission denied` (not root)
and still starts. The `tpm-hw` build itself needs `libtss2-dev`/`tpm2-tss-devel`
(absent here), and `vtpm` needs a built component — so the *runtime* run is the
equipped-node step below.

**Remaining — run on an equipped node** (real TPM, or swtpm + the TSS libs, or a
built vTPM component):
```sh
# vTPM (in-process): build the feature, point at a built component + state file
TPM_VTPM_COMPONENT=… cargo test -p vtpm-backend                              # real-TPM tests
TPM_VTPM_COMPONENT=… cargo test -p citadel-agent --features vtpm --test mtls_transport
# Deployed agent against a real/sw TPM:
CITADEL_TPM_BACKEND=tcti CITADEL_TPM_TCTI=swtpm:path=/run/swtpm.sock \
  cargo run -p citadel-agent --features tpm-hw   # (+ CITADEL_SEED etc.)
```
Bring up two `citadel-agent` processes (see `crates/citadel-agent/src/main.rs`
env config) to watch real attestation + mTLS gossip — and this also completes the
**firmware-ships-and-replays** validation deferred from Task 2 (a real backend's
quote matches its own measured state).

---

## What to send back
- New fixtures that **pass** (commit them) — they become permanent corpus.
- Any **failing** fixture + the test output (real-data warts to harden).
- For Task 2/3: whether you want me to implement the `/sys` readers and the
  real-TPM backend wiring first (then you run), or a different split.
