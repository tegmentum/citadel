# A1 event-log corpus — CLOSED

**Status: closed (2026-06-07) on a Linux/Fedora workstation.** `tpm_core::eventlog`
`parse_tcg` + `replay` are validated against a real OVMF/UEFI measured-boot log.

- Fixture: `crates/tpm-core/tests/fixtures/eventlog/ubuntu-24.04-ovmf-amd64.{bin,sha256}`
  — a genuine crypto-agile UEFI log (4 banks, `EV_S_CRTM_VERSION`,
  `EV_EFI_PLATFORM_FIRMWARE_BLOB`, secure-boot `EV_EFI_VARIABLE_DRIVER_CONFIG`,
  shim/grub `EV_EFI_BOOT_SERVICES_*`, `EV_IPL`).
- Harness: `cargo test -p tpm-core --test eventlog_corpus` — green; 11 firmware
  PCRs (0–9, 14) replay exactly to the live quote.
- Captured with `scripts/capture-eventlog.sh` (now turnkey on Fedora — just
  point it at a cloud image; OVMF is autodetected).

## Reproduce / add more samples
```sh
sudo dnf install -y qemu-system-x86 edk2-ovmf swtpm genisoimage qemu-img  # Fedora
# (Debian: qemu-system-x86 ovmf swtpm cloud-image-utils)

wget -O cloud.img https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
# don't dirty the base image — boot a throwaway overlay:
qemu-img create -f qcow2 -F qcow2 -b cloud.img run.qcow2

IMAGE=$PWD/run.qcow2 NAME=ubuntu-24.04-ovmf-amd64 \
  timeout 400 scripts/capture-eventlog.sh
```
The script boots the guest under OVMF + swtpm (KVM), the guest's cloud-init
(`scripts/eventlog-guest-cloud-init.yaml`) copies the log + sha256 PCRs back over
a 9p share and powers off, then the corpus harness runs. Capture from a few
firmwares for breadth — drop each `<name>.{bin,sha256}` pair in the fixtures dir.

## Fixture format
- `<name>.bin` — raw `binary_bios_measurements` (TCG crypto-agile log).
- `<name>.sha256` — the live quote, one `<pcr_index> <hex_sha256>` per line.

The harness replays the log and, **for every PCR the log measures**, asserts the
replayed value equals the quote. Quote PCRs the firmware log can't explain are
reported and skipped — notably **PCR 10 (IMA)**, extended by the kernel at
runtime into a *separate* IMA log, and never-extended all-zero PCRs (11–13, 15).

## The four things that actually blocked this (don't relearn them)
1. **swtpm socket wiring.** QEMU's `tpm-emulator` backend talks to swtpm's
   **`--ctrl`** socket — it sends `CMD_SET_DATAFD` over it to set up the data
   channel itself. The old script created a separate `--server` socket and fed
   *that* to the chardev → `Failed to send CMD_SET_DATAFD` → every firmware TPM
   command halted the vCPU (0% CPU, silent). Point the chardev at `--ctrl`.
   This hit **both** SeaBIOS and OVMF and looked like "firmware won't boot."
2. **Use the 4MB OVMF build.** The legacy 2MB `OVMF_CODE.fd` does not autoboot a
   stock Ubuntu cloud disk under blank NVRAM — it sits in the UEFI Shell,
   headless and invisible. The 4MB build (`OVMF_CODE_4M.qcow2` on Fedora, shipped
   as qcow2 → the script converts it to raw for pflash) boots shim→grub→kernel.
3. **No `-no-reboot`.** shim does a one-time `Reset System` on first boot with a
   fresh varstore; `-no-reboot` makes QEMU exit there instead of completing.
4. **Mask `systemd-networkd-wait-online`.** Under QEMU user-mode networking the
   NIC doesn't satisfy it; its "no limit" job stalls `multi-user.target` so
   cloud-init's `runcmd` (the copy + poweroff) never runs. The guest cloud-init
   masks it early in `bootcmd`.

swtpm also won't create its own `--tpmstate dir` — the script `mkdir`s it.

## swtpm state-dir gotcha & misc
- `swtpm socket --tpmstate dir=X` requires `X` to pre-exist.
- A TPM **1.2** host (sysfs has `pcr-sha1`, no `pcr-sha256`) can't supply a
  TPM2/crypto-agile corpus entry — use the QEMU+swtpm lab, which gives TPM 2.0.

## What closing A1 unblocks
- **A3** — structured `ArtifactIdentity` extraction from the real
  `EV_EFI_BOOT_SERVICES_APPLICATION` / `EV_IPL` events now in the corpus.
- **B1-firmware tail** — `read_event_log` on a real `/sys` path (parser ready).
- **A2 tail** — parsing the real `EV_EFI_VARIABLE_AUTHORITY` `EFI_SIGNATURE_DATA`
  wrapper against real authority blobs.

## macOS notes (why it stalled there originally)
- `qemu-system-x86_64` on Apple Silicon is TCG-only (no same-arch HVF) → emulated
  x86 boot is too slow; and `-serial file:` silently doesn't capture on the brew
  build, so the (mis-wired) TPM hang and the 2MB-OVMF UEFI-Shell stall were both
  invisible. All of this Just Works on a Linux/KVM box.
