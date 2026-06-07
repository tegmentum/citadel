#!/usr/bin/env bash
# Turnkey A1 capture: boot a UEFI Linux guest under QEMU + OVMF + swtpm (a real
# software TPM 2.0) so OVMF produces a genuine measured-boot event log, then
# collect /sys/.../binary_bios_measurements + the live sha256 PCRs into
# crates/tpm-core/tests/fixtures/eventlog/ — no physical hardware.
#
# Prereqs:
#   Linux (Fedora):  sudo dnf install qemu-system-x86 edk2-ovmf swtpm genisoimage
#   Linux (Debian):  sudo apt-get install qemu-system-x86 ovmf swtpm cloud-image-utils
#   macOS:           brew install qemu swtpm
#   plus a cloud-init-enabled, UEFI-bootable Linux qcow2 with a TPM-enabled
#   kernel (Ubuntu/Fedora cloud images work). Pass it as $IMAGE.
#
# Usage:
#   IMAGE=/path/to/cloud.qcow2 NAME=ubuntu-24.04 scripts/capture-eventlog.sh
#
# The guest runs scripts/eventlog-guest-cloud-init.yaml (mount 9p host share,
# copy the log + PCRs, poweroff). On exit, the fixtures are validated with
#   cargo test -p tpm-core --test eventlog_corpus
#
# Gotchas baked into this script (learned the hard way — see
# docs/a1-capture-handoff.md):
#   * Use the 4MB OVMF build. The legacy 2MB OVMF_CODE.fd does NOT autoboot a
#     stock Ubuntu cloud disk under blank NVRAM; it sits in the UEFI Shell,
#     headless and invisible.
#   * QEMU's tpm-emulator backend talks to swtpm's --ctrl socket (it sends
#     CMD_SET_DATAFD over it to set up the data channel itself). Point the
#     chardev at --ctrl, not a separate --server socket, or every TPM command
#     hangs the vCPU.
#   * No -no-reboot: shim does a one-time reset on first boot with fresh NVRAM;
#     -no-reboot would make QEMU exit there instead of completing the boot.
set -euo pipefail

NAME="${NAME:-sample}"
IMAGE="${IMAGE:?set IMAGE=/path/to/uefi-linux.qcow2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/crates/tpm-core/tests/fixtures/eventlog"
SCRIPTS="$ROOT/scripts"

# OVMF: honor an explicit OVMF_CODE/OVMF_VARS pair; otherwise autodetect,
# preferring the 4MB build over the legacy 2MB one.
first_existing() { for p in "$@"; do [ -f "$p" ] && { printf '%s\n' "$p"; return; }; done; }
OVMF_CODE="${OVMF_CODE:-$(first_existing \
  /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
  /usr/share/edk2/ovmf/OVMF_CODE_4M.qcow2 \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/edk2/ovmf/OVMF_CODE.fd)}"
OVMF_VARS_SRC="${OVMF_VARS:-$(first_existing \
  /opt/homebrew/share/qemu/edk2-i386-vars.fd \
  /usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2 \
  /usr/share/OVMF/OVMF_VARS_4M.fd \
  /usr/share/edk2/ovmf/OVMF_VARS_4M.fd \
  /usr/share/OVMF/OVMF_VARS.fd \
  /usr/share/edk2/ovmf/OVMF_VARS.fd)}"

command -v qemu-system-x86_64 >/dev/null || { echo "need qemu-system-x86_64"; exit 1; }
command -v qemu-img >/dev/null || { echo "need qemu-img"; exit 1; }
command -v swtpm >/dev/null || { echo "need swtpm"; exit 1; }
[ -n "${OVMF_CODE:-}" ] && [ -f "$OVMF_CODE" ] || { echo "OVMF firmware not found (set OVMF_CODE=/path/to/OVMF_CODE*.fd)"; exit 1; }
[ -n "${OVMF_VARS_SRC:-}" ] && [ -f "$OVMF_VARS_SRC" ] || { echo "OVMF vars not found (set OVMF_VARS=/path/to/OVMF_VARS*.fd)"; exit 1; }

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
SWTPM_PID=""
cleanup() { [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

# pflash needs raw images; some distros ship OVMF as qcow2. Convert code (kept
# read-only) and vars (writable copy) into WORK as needed.
is_qcow2() { qemu-img info --output=json "$1" 2>/dev/null | grep -q '"format": *"qcow2"'; }
if is_qcow2 "$OVMF_CODE"; then
  qemu-img convert -O raw "$OVMF_CODE" "$WORK/code.fd"; OVMF_CODE="$WORK/code.fd"
fi
if is_qcow2 "$OVMF_VARS_SRC"; then
  qemu-img convert -O raw "$OVMF_VARS_SRC" "$WORK/vars.fd"
else
  cp "$OVMF_VARS_SRC" "$WORK/vars.fd"
fi

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
# The chardev below points at THIS --ctrl socket; QEMU's tpm-emulator backend
# sets up the data channel itself over it. (A separate --server socket here, fed
# to the chardev, makes CMD_SET_DATAFD fail and hangs the guest.)
mkdir -p "$WORK/tpm"   # swtpm requires its state dir to pre-exist (it won't mkdir)
swtpm socket --tpm2 --tpmstate dir="$WORK/tpm" \
  --ctrl type=unixio,path="$WORK/swtpm-sock" --flags startup-clear &
SWTPM_PID=$!
for _ in $(seq 1 40); do [ -S "$WORK/swtpm-sock" ] && break; sleep 0.05; done

# --- boot: OVMF measures into the swtpm; guest cloud-init collects + powers off ---
ACCEL="$([ "$(uname -s)" = Darwin ] && echo hvf || echo kvm)"
qemu-system-x86_64 \
  -machine q35,accel="$ACCEL" -m 2048 -nographic \
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
