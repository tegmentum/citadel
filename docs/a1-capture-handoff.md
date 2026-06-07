# A1 event-log corpus — Linux workstation handoff

Pick up here to **close roadmap A1**: validate `tpm_core::eventlog::parse_tcg` +
`replay` against real firmware measured-boot logs. Everything *around* the
capture is built and committed; the only thing left is getting one or more real
`binary_bios_measurements` files into the corpus and running the harness. On a
Linux box this is minutes (it stalled on macOS only because the host lacks
ext4/nbd/libguestfs and `qemu-system-x86_64` had no acceleration — see
**macOS notes** at the end).

## What's already done (no need to redo)
- **Parser + replay**: `crates/tpm-core/src/eventlog.rs` — `parse_tcg`
  (crypto-agile TCG log, multi-bank, padding/terminator-tolerant), `replay`,
  `explains` (replay == quote).
- **Corpus harness**: `crates/tpm-core/tests/eventlog_corpus.rs` — scans the
  fixtures dir, asserts each log parses and its sha256 replay equals the
  expected PCRs. No-op until fixtures exist.
- **Capture scripts**: `scripts/capture-eventlog.sh` (x86), 
  `scripts/capture-eventlog-aarch64.sh` (arm64/HVF), 
  `scripts/eventlog-guest-cloud-init.yaml` (guest-side copy + poweroff).
- **swtpm lifecycle**: `tpm_core::backend::SwtpmManager`.
- The arm64 Ubuntu cloud image is cached at
  `~/.cache/citadel-a1/noble-arm64.img` (macOS box only; re-fetch on Linux).

## Fixture format
Each sample is two files in `crates/tpm-core/tests/fixtures/eventlog/`:
- `<name>.bin` — raw `binary_bios_measurements` (the TCG crypto-agile log)
- `<name>.sha256` — expected quoted PCRs, one per line: `<pcr_index> <hex_sha256>`

The harness asserts `replay(<name>.bin)["sha256"][i] == <hex>` for each line.

---

## Path A — fastest: copy a real log off any Linux box (no QEMU)
If the workstation (or any VM/server) has a TPM, this is ~10 seconds and gives a
genuine firmware corpus entry:

```sh
cd <citadel>/crates/tpm-core/tests/fixtures/eventlog
N=$(hostnamectl --static 2>/dev/null || hostname)
sudo cp /sys/kernel/security/tpm0/binary_bios_measurements "$N.bin"
for p in $(seq 0 15); do
  v=$(cat /sys/class/tpm/tpm0/pcr-sha256/$p 2>/dev/null | tr -d ' \n')
  [ -n "$v" ] && printf '%s %s\n' "$p" "$v"
done > "$N.sha256"

cd <citadel> && cargo test -p tpm-core --test eventlog_corpus -- --nocapture
```

`/sys/kernel/security/...` needs root and `securityfs` mounted; the PCRs come
from the kernel's sysfs TPM interface. Capture from a few different machines /
firmwares for breadth.

---

## Path B — the QEMU + OVMF + swtpm lab (reproducible, no hardware)
Best on Linux because acceleration and guest-fs tooling all work.

```sh
sudo apt-get install -y qemu-system-x86 ovmf swtpm cloud-image-utils   # Debian/Ubuntu
# (Fedora: qemu-system-x86 edk2-ovmf swtpm cloud-utils)

# a UEFI cloud image with a TPM-enabled kernel:
wget -O cloud.img https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

IMAGE=$PWD/cloud.img NAME=ubuntu-24.04-amd64 <citadel>/scripts/capture-eventlog.sh
```

On Linux the x86 script gets **KVM** acceleration (the script already selects
`accel=kvm`), `cloud-localds` builds the cloud-init seed, and a 9p share carries
the fixtures back out. The script runs the harness automatically at the end.

> Note: the script's cloud-init (`scripts/eventlog-guest-cloud-init.yaml`)
> mounts the 9p `host` share, copies the log + PCRs, and powers off. If your
> guest image uses a different init, adapt that file.

---

## Path C — direct-kernel boot (#2), now that extraction works on Linux
This was blocked on macOS (no ext4/libguestfs). On Linux:

```sh
# extract the image's own kernel + initrd (matches the rootfs):
sudo apt-get install -y libguestfs-tools
virt-get-kernel -a cloud.img -o /tmp/a1     # -> /tmp/a1/vmlinuz-* and initramfs-*

# boot directly through OVMF (so measured boot still runs) + swtpm:
swtpm socket --tpm2 --tpmstate dir=/tmp/a1/tpm --ctrl type=unixio,path=/tmp/a1/ctrl \
  --server type=unixio,path=/tmp/a1/sock --flags startup-clear &
qemu-system-x86_64 -machine q35,accel=kvm -m 2048 -nographic \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/tmp/a1/vars.fd \
  -chardev socket,id=chrtpm,path=/tmp/a1/sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
  -drive if=virtio,format=qcow2,file=cloud.img \
  -kernel /tmp/a1/vmlinuz-* -initrd /tmp/a1/initramfs-* \
  -append "root=/dev/vda1 console=ttyS0 ro" \
  -virtfs local,path=<citadel>/crates/tpm-core/tests/fixtures/eventlog,mount_tag=host,security_model=mapped-xattr,id=host
# (then `mount -t 9p ... host /mnt/host` and copy as in Path A, or reuse cloud-init)
```

Direct `-kernel` avoids the empty-NVRAM UEFI-Shell autoboot stall entirely.
(`cp /tmp/a1/OVMF_VARS.fd /tmp/a1/vars.fd` first, or `dd` a 540K zero vars file
matching your OVMF build.)

---

## Validate + harden loop
```sh
cargo test -p tpm-core --test eventlog_corpus -- --nocapture
```
- **Green** → A1 is closed. Commit the fixtures.
- **Parse/replay failure** → that's the real-firmware wart we wanted to find.
  Send me (or capture in an issue) the failing `<name>.bin` + the harness
  output; the fix is in `eventlog.rs::parse_tcg` (it's already tolerant of
  multi-bank records and trailing padding; new quirks get added the same way,
  with a regression test built from the real bytes).

## What closing A1 unblocks
- **A3** — structured `ArtifactIdentity` extraction from real events
  (`EV_EFI_BOOT_SERVICES_APPLICATION`, `EV_IPL` cmdline) — needs the corpus.
- **B1-firmware tail** — `read_event_log` on a real `/sys` path (the parser is
  ready; it's just read-the-file + wire into `logship::append_event`).
- **A2 tail** — parsing the real `EV_EFI_VARIABLE_AUTHORITY` `EFI_SIGNATURE_DATA`
  wrapper, validated against real authority blobs.

## macOS notes (why it stalled there — don't repeat)
- `qemu-system-x86_64` on Apple Silicon is **TCG-only** (no same-arch HVF) →
  emulated x86 boot is too slow. The arm64 path (`-machine virt,accel=hvf`)
  *does* boot fast, but UEFI guests need an autoboot fix.
- Empty OVMF NVRAM → firmware sits in the **UEFI Shell**; `startup.nsh` chainload
  didn't take, and it can't be debugged headlessly because **`-serial file:`
  silently doesn't capture** on the brew QEMU build (only `-serial stdio` does).
- No `libguestfs` / `ext4fuse` / `/dev/nbd` on macOS → can't extract the guest
  kernel for #2. All of these Just Work on Linux.
