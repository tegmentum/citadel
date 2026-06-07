#!/usr/bin/env bash
# A1 capture on Apple Silicon (arm64) using HVF — fast, native virtualization.
# qemu-system-aarch64 + arm64 OVMF + swtpm boots a UEFI Linux guest that
# produces a real TCG measured-boot event log; the guest copies it (+ live
# sha256 PCRs) into crates/tpm-core/tests/fixtures/eventlog/ via a 9p share.
#
# Differences from the x86 script: -machine virt, -cpu host -accel hvf,
# tpm-tis-device (arm) instead of tpm-tis, and OVMF as two 64MiB pflash images.
#
# Prereqs: brew install qemu swtpm ; an arm64 UEFI cloud qcow2 (IMAGE).
# Usage:   IMAGE=~/.cache/citadel-a1/noble-arm64.img NAME=ubuntu-24.04-arm64 \
#            scripts/capture-eventlog-aarch64.sh
set -euo pipefail

NAME="${NAME:-sample-arm64}"
IMAGE="${IMAGE:?set IMAGE=/path/to/arm64-uefi-linux.qcow2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/crates/tpm-core/tests/fixtures/eventlog"
SCRIPTS="$ROOT/scripts"
OVMF_CODE="${OVMF_CODE:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"

command -v qemu-system-aarch64 >/dev/null || { echo "need qemu (brew install qemu)"; exit 1; }
command -v swtpm >/dev/null || { echo "need swtpm (brew install swtpm)"; exit 1; }
[ -f "$OVMF_CODE" ] || { echo "arm64 OVMF not at $OVMF_CODE"; exit 1; }

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
SWTPM_PID=""
cleanup() { [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

# OVMF needs code + a writable vars pflash, each padded to the flash size (64MiB).
cp "$OVMF_CODE" "$WORK/code.fd"
dd if=/dev/zero of="$WORK/vars.fd" bs=1m count=64 2>/dev/null

# A writable overlay so we never mutate the base image.
qemu-img create -f qcow2 -F qcow2 -b "$IMAGE" "$WORK/overlay.qcow2" >/dev/null

# cloud-init seed.
sed "s/__NAME__/$NAME/g" "$SCRIPTS/eventlog-guest-cloud-init.yaml" > "$WORK/user-data"
printf 'instance-id: a1-capture\nlocal-hostname: a1-capture\n' > "$WORK/meta-data"
if command -v mkisofs >/dev/null; then
  mkisofs -output "$WORK/seed.iso" -volid cidata -joliet -rock "$WORK/user-data" "$WORK/meta-data" 2>/dev/null
elif command -v hdiutil >/dev/null; then
  mkdir -p "$WORK/cidata" && cp "$WORK/user-data" "$WORK/meta-data" "$WORK/cidata/"
  hdiutil makehybrid -iso -joliet -default-volume-name cidata -o "$WORK/seed.iso" "$WORK/cidata" >/dev/null
else
  echo "need mkisofs or hdiutil to build the cloud-init seed"; exit 1
fi

mkdir -p "$WORK/tpm"
swtpm socket --tpm2 --tpmstate dir="$WORK/tpm" \
  --ctrl type=unixio,path="$WORK/swtpm-ctrl" \
  --server type=unixio,path="$WORK/swtpm-sock" --flags startup-clear &
SWTPM_PID=$!
for _ in $(seq 1 40); do [ -S "$WORK/swtpm-sock" ] && break; sleep 0.05; done

qemu-system-aarch64 \
  -machine virt,accel=hvf -cpu host -m 2048 -nographic -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file="$WORK/code.fd" \
  -drive if=pflash,format=raw,file="$WORK/vars.fd" \
  -chardev socket,id=chrtpm,path="$WORK/swtpm-sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis-device,tpmdev=tpm0 \
  -drive if=virtio,format=qcow2,file="$WORK/overlay.qcow2" \
  -drive if=virtio,format=raw,file="$WORK/seed.iso" \
  -virtfs local,path="$OUT_DIR",mount_tag=host,security_model=mapped-xattr,id=host \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 || true

if [ -f "$OUT_DIR/$NAME.bin" ] && [ -f "$OUT_DIR/$NAME.sha256" ]; then
  echo "captured: $OUT_DIR/$NAME.{bin,sha256}"
  ( cd "$ROOT" && cargo test -p tpm-core --test eventlog_corpus -- --nocapture )
else
  echo "no fixtures produced — see notes in the script header"; exit 1
fi
