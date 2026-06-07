# Event-log corpus (A1)

Drop real measured-boot logs here to validate `parse_tcg` + `replay` against
firmware that actually exists. Each sample is two files:

* `<name>.bin`     — raw `binary_bios_measurements` (the TCG crypto-agile log)
* `<name>.sha256`  — expected quoted PCRs, one per line: `<pcr_index> <hex_sha256>`
                     (the live PCR values the log must replay to)

`eventlog_corpus.rs` scans this directory: every `.bin` with a sidecar is
parsed and its sha256 replay is asserted equal to the expected values. With no
fixtures the test is a no-op, so it's safe to commit empty.

Generate samples with `scripts/capture-eventlog.sh` (QEMU + OVMF + swtpm).
