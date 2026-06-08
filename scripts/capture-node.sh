#!/usr/bin/env bash
# Run ON a real Linux node (bare metal, or a TPM-equipped VM) to capture its
# REAL firmware measured-boot log and IMA runtime list into the test fixtures,
# then validate the parsers against them. This is the broadest parser test there
# is: real *vendor* firmware (not just OVMF) and the node's own runtime list.
#
# Needs root (securityfs) and a TPM. Outputs go to the fixture dirs; commit the
# ones that validate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${NAME:-$(hostnamectl --static 2>/dev/null || hostname | tr -cd 'a-zA-Z0-9._-')}"
EVDIR="$ROOT/crates/tpm-core/tests/fixtures/eventlog"
IMADIR="$ROOT/crates/tpm-core/tests/fixtures/ima"
mkdir -p "$EVDIR" "$IMADIR"
me="$(id -u):$(id -g)"
got_any=0

# --- firmware measured-boot log + live PCRs (A1 breadth / B1) ---
BIOS=/sys/kernel/security/tpm0/binary_bios_measurements
if sudo test -r "$BIOS"; then
  sudo cp "$BIOS" "$EVDIR/$NAME.bin" && sudo chown "$me" "$EVDIR/$NAME.bin"
  : > "$EVDIR/$NAME.sha256"
  for p in $(seq 0 23); do
    v=$(cat "/sys/class/tpm/tpm0/pcr-sha256/$p" 2>/dev/null | tr -d ' \n')
    [ -n "$v" ] && printf '%s %s\n' "$p" "$v" >> "$EVDIR/$NAME.sha256"
  done
  echo "captured firmware log: $EVDIR/$NAME.bin ($(stat -c%s "$EVDIR/$NAME.bin") bytes), $(wc -l < "$EVDIR/$NAME.sha256") PCRs"
  got_any=1
else
  echo "no firmware event log at $BIOS (no TPM, or measured boot off) — skipping"
fi

# --- IMA runtime list (C1) ---
IMA=/sys/kernel/security/ima/ascii_runtime_measurements
if sudo test -r "$IMA"; then
  sudo cp "$IMA" "$IMADIR/$NAME.ascii" && sudo chown "$me" "$IMADIR/$NAME.ascii"
  echo "captured IMA list: $IMADIR/$NAME.ascii ($(wc -l < "$IMADIR/$NAME.ascii") entries)"
  echo "  templates: $(awk '{print $3}' "$IMADIR/$NAME.ascii" | sort | uniq -c | tr '\n' ' ')"
  got_any=1
else
  echo "no IMA list at $IMA (IMA inactive; boot with ima_policy=tcb for a full list) — skipping"
fi

[ "$got_any" = 1 ] || { echo "nothing captured (is there a TPM? try a TPM-equipped host)"; exit 1; }

# --- validate the parsers against what we captured ---
echo "=== validating ==="
( cd "$ROOT" && cargo test -p tpm-core --test eventlog_corpus --test ima_corpus -- --nocapture )
echo
echo "If both passed, commit the new fixture(s). If a parse/replay failed, that's"
echo "a real-firmware/kernel wart worth reporting with the failing fixture + output."
