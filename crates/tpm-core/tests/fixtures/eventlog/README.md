# Event-log corpus (A1)

Drop real measured-boot logs here to validate `parse_tcg` + `replay` against
firmware that actually exists. Each sample is two files:

* `<name>.bin`     — raw `binary_bios_measurements` (the TCG crypto-agile log)
* `<name>.sha256`  — expected quoted PCRs, one per line: `<pcr_index> <hex_sha256>`
                     (the live PCR values the log must replay to)

`eventlog_corpus.rs` scans this directory: every `.bin` with a sidecar is
parsed, and for **every PCR the firmware log measures** the sha256 replay is
asserted equal to the quoted value. With no fixtures the test is a no-op, so
it's safe to commit empty.

The sidecar is the full live quote (PCRs 0–15). The harness checks only the
PCRs the firmware log actually measures (here 0–9 and 14); quote PCRs the log
can't explain are reported and skipped — notably **PCR 10 (IMA)**, which the
Linux kernel extends at runtime and records in a *separate* IMA log, and the
never-extended all-zero PCRs (11–13, 15).

Generate samples with `scripts/capture-eventlog.sh` (QEMU + OVMF + swtpm); see
`docs/a1-capture-handoff.md` for the full procedure and gotchas.

Committed samples:

* `ubuntu-24.04-ovmf-amd64` — Ubuntu 24.04 (noble) cloud image booted under the
  4MB OVMF (edk2) + swtpm 2.0 on QEMU/q35 with KVM. A genuine crypto-agile UEFI
  measured-boot log: `Spec ID Event03` with four banks (sha1/sha256/sha384/
  sha512), `EV_S_CRTM_VERSION`, `EV_EFI_PLATFORM_FIRMWARE_BLOB`, secure-boot
  `EV_EFI_VARIABLE_DRIVER_CONFIG` (PCR 7), shim/grub `EV_EFI_BOOT_SERVICES_*`
  and `EV_IPL`.
