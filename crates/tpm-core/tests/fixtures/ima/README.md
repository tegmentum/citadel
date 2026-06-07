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
