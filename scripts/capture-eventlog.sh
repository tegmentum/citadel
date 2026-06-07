#!/usr/bin/env bash
# Turnkey A1 capture: boot a UEFI Linux guest under QEMU + OVMF + swtpm (a real
# software TPM 2.0) so OVMF produces a genuine measured-boot event log, then
# collect /sys/.../binary_bios_measurements + the live sha256 PCRs into
# crates/tpm-core/tests/fixtures/eventlog/ — no physical hardware.
#
# Prereqs (macOS / Homebrew):
#   brew install qemu swtpm
#   plus a cloud-init-enabled, UEFI-bootable Linux qcow2 with a TPM-enabled
#   kernel (Ubuntu/Fedora cloud images work). Pass it as $IMAGE.
#
# Usage:
#   IMAGE=/path/to/cloud.qcow2 NAME=ubuntu-24.04 scripts/capture-eventlog.sh
#
# The guest runs scripts/eventlog-guest-cloud-init.yaml (mount 9p host share,
# copy the log + PCRs, poweroff). On exit, the fixtures are validated with
#   cargo test -p tpm-core --test eventlog_corpus
set -euo pipefail

NAME="${NAME:-sample}"
IMAGE="${IMAGE:?set IMAGE=/path/to/uefi-linux.qcow2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/crates/tpm-core/tests/fixtures/eventlog"
SCRIPTS="$ROOT/scripts"
OVMF_CODE="${OVMF_CODE:-/opt/homebrew/share/qemu/edk2-x86_64-code.fd}"
OVMF_VARS_SRC="${OVMF_VARS:-/opt/homebrew/share/qemu/edk2-i386-vars.fd}"

command -v qemu-system-x86_64 >/dev/null || { echo "need qemu (brew install qemu)"; exit 1; }
command -v swtpm >/dev/null || { echo "need swtpm (brew install swtpm)"; exit 1; }
[ -f "$OVMF_CODE" ] || { echo "OVMF firmware not at $OVMF_CODE (set OVMF_CODE=)"; exit 1; }

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
SWTPM_PID=""
cleanup() { [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
cp "$OVMF_VARS_SRC" "$WORK/vars.fd"

# --- cloud-init seed (user-data templated with NAME, + empty meta-data) ---
sed "s/__NAME__/$NAME/g" "$SCRIPTS/eventlog-guest-cloud-init.yaml" > "$WORK/user-data"
printf 'instance-id: a1-capture\nlocal-hostname: a1-capture\n' > "$WORK/meta-data"
if command -v cloud-localds >/dev/null; then
  cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"
elif command -v mkisofs >/dev/null; then
  mkisofs -output "$WORK/seed.iso" -volid cidata -joliet -rock "$WORK/user-data" "$WORK/meta-data"
elif command -v genisoimage >/dev/null; then
  genisoimage -output "$WORK/seed.iso" -volid cidata -joliet -rock "$WORK/user-data" "$WORK/meta-data"
elif command -v hdiutil >/dev/null; then
  mkdir -p "$WORK/cidata" && cp "$WORK/user-data" "$WORK/meta-data" "$WORK/cidata/"
  hdiutil makehybrid -iso -joliet -default-volume-name cidata -o "$WORK/seed.iso" "$WORK/cidata" >/dev/null
else
  echo "need a tool to build the cloud-init seed ISO: cloud-localds | mkisofs | genisoimage | hdiutil (macOS)"; exit 1
fi

# --- swtpm: a real TPM 2.0 on a unix socket QEMU drives during boot ---
swtpm socket --tpm2 --tpmstate dir="$WORK/tpm" \
  --ctrl type=unixio,path="$WORK/swtpm-ctrl" \
  --server type=unixio,path="$WORK/swtpm-sock" --flags startup-clear &
SWTPM_PID=$!
for _ in $(seq 1 40); do [ -S "$WORK/swtpm-sock" ] && break; sleep 0.05; done

# --- boot: OVMF measures into the swtpm; guest cloud-init collects + powers off ---
ACCEL="$([ "$(uname -s)" = Darwin ] && echo hvf || echo kvm)"
qemu-system-x86_64 \
  -machine q35,accel="$ACCEL" -m 2048 -nographic -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WORK/vars.fd" \
  -chardev socket,id=chrtpm,path="$WORK/swtpm-sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
  -drive if=virtio,format=qcow2,file="$IMAGE" \
  -drive if=virtio,format=raw,file="$WORK/seed.iso" \
  -virtfs local,path="$OUT_DIR",mount_tag=host,security_model=mapped-xattr,id=host \
  -netdev user,id=n0 -device virtio-net,netdev=n0 || true

if [ -f "$OUT_DIR/$NAME.bin" ] && [ -f "$OUT_DIR/$NAME.sha256" ]; then
  echo "captured: $OUT_DIR/$NAME.{bin,sha256}"
  ( cd "$ROOT" && cargo test -p tpm-core --test eventlog_corpus -- --nocapture )
else
  echo "no fixtures produced — check the guest booted, has a TPM + IMA, and ran cloud-init"
  exit 1
fi
