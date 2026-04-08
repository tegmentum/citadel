#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.local/bin"

echo "Building tpm (release)..."
cargo build --release -p tpm 2>&1 | tail -1

mkdir -p "$INSTALL_DIR"
cp target/release/tpm "$INSTALL_DIR/tpm"
chmod +x "$INSTALL_DIR/tpm"

echo "Installed to ${INSTALL_DIR}/tpm"

# Check if INSTALL_DIR is in PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    echo "Add to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo ""
echo "Run: tpm --help"
