#!/usr/bin/env bash
# Capture a real measured-boot event log for the A1 corpus, with no physical
# hardware: QEMU + OVMF (UEFI firmware) + swtpm (software TPM) booting a Linux
# guest, then pull /sys/kernel/security/tpm0/binary_bios_measurements and the
# live PCR values into crates/tpm-core/tests/fixtures/eventlog/.
#
# Prereqs (macOS / Homebrew):
#   brew install qemu swtpm
#   plus a UEFI-bootable Linux cloud image with a TPM-enabled kernel + IMA, e.g.
#   an Ubuntu/Fedora cloud qcow2. Pass it as $IMAGE.
#
# Usage:
#   IMAGE=/path/to/cloud-image.qcow2 NAME=ubuntu-24.04 scripts/capture-eventlog.sh
#
# The guest must, after boot, copy the two files out (via virtiofs/scp/9p or a
# cloud-init runcmd). This script wires a 9p share at /mnt/host; the guest's
# cloud-init should run:
#   cp /sys/kernel/security/tpm0/binary_bios_measurements /mnt/host/$NAME.bin
#   for p in 0 1 2 3 4 5 6 7 8 9; do \
#     printf '%s %s\n' "$p" "$(cat /sys/class/tpm/tpm0/pcr-sha256/$p)"; \
#   done > /mnt/host/$NAME.sha256
#
# This file documents the reproducible path; adapt the guest-side copy to your
# image's init system. It deliberately does NOT auto-download a multi-GB image.
set -euo pipefail

NAME="${NAME:-sample}"
IMAGE="${IMAGE:?set IMAGE=/path/to/uefi-linux.qcow2}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/crates/tpm-core/tests/fixtures/eventlog"
OVMF_CODE="${OVMF_CODE:-/opt/homebrew/share/qemu/edk2-x86_64-code.fd}"
OVMF_VARS_SRC="${OVMF_VARS:-/opt/homebrew/share/qemu/edk2-i386-vars.fd}"

command -v qemu-system-x86_64 >/dev/null || { echo "need qemu (brew install qemu)"; exit 1; }
command -v swtpm >/dev/null || { echo "need swtpm (brew install swtpm)"; exit 1; }
[ -f "$OVMF_CODE" ] || { echo "OVMF firmware not found at $OVMF_CODE"; exit 1; }

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null || true' EXIT
cp "$OVMF_VARS_SRC" "$WORK/vars.fd"

# 1) Start swtpm (TPM 2.0) on a unix socket.
swtpm socket --tpm2 --tpmstate dir="$WORK/tpm" \
  --ctrl type=unixio,path="$WORK/swtpm-ctrl" \
  --server type=unixio,path="$WORK/swtpm-sock" --flags startup-clear &
SWTPM_PID=$!
sleep 1

# 2) Boot the guest with OVMF + the swtpm device + a 9p host share for output.
qemu-system-x86_64 \
  -machine q35,accel=hvf -m 2048 -nographic \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WORK/vars.fd" \
  -chardev socket,id=chrtpm,path="$WORK/swtpm-sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -drive if=virtio,format=qcow2,file="$IMAGE" \
  -virtfs local,path="$OUT_DIR",mount_tag=host,security_model=mapped-xattr,id=host \
  -netdev user,id=n0 -device virtio-net,netdev=n0

# After the guest copies $NAME.bin + $NAME.sha256 into $OUT_DIR (9p mount_tag
# "host"), `cargo test -p tpm-core --test eventlog_corpus` validates them.
echo "If the guest wrote them, fixtures are in: $OUT_DIR"
ls -la "$OUT_DIR"
