# IMA runtime-measurement corpus (C1)

Drop real Linux IMA lists here to validate the `tpm_core::ima` parser against
what kernels actually emit. One file per sample:

* `<name>.ascii` — the raw `/sys/kernel/security/ima/ascii_runtime_measurements`

`ima_corpus.rs` parses every `.ascii`, asserts it has entries (at least the
`boot_aggregate`) and that no lines are skipped (the parser understood every
template). Empty dir = no-op.

Capture (needs IMA active — boot the guest with `ima_policy=tcb` for a rich list;
without a policy you still get `boot_aggregate`):

    sudo cp /sys/kernel/security/ima/ascii_runtime_measurements name.ascii

Or, with no host reboot, in the QEMU lab (SeaBIOS direct `-kernel` + swtpm so
`boot_aggregate` is TPM-real, with `ima_policy=tcb` on the cmdline) — see
`docs/a1-capture-handoff.md` for the same machinery.

Committed samples:

* `ubuntu-24.04-tcb-amd64` — Ubuntu 24.04 (noble) cloud kernel 6.8.0 booted under
  `ima_policy=tcb`: 3619 `ima-ng`/sha256 entries (TPM-backed `boot_aggregate`,
  then executables, libraries, kernel modules, and root-read config files).
