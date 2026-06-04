#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.local/bin"

echo "Building tpm (release, with vtpm) from published git dependencies..."

# The build depends on secure-log / vtpm-wasm as git dependencies. If a
# local development override is present (a gitignored .cargo/config.toml
# that [patch]es those deps to sibling working copies), set it aside for
# the release build so install.sh always builds against the published git
# dependencies. It is restored when the script exits (success or failure).
if [ -f .cargo/config.toml ]; then
    mv .cargo/config.toml .cargo/config.toml.install-bak
    trap 'mv .cargo/config.toml.install-bak .cargo/config.toml' EXIT
fi

cargo build --release --features vtpm -p tpm 2>&1 | tail -1

mkdir -p "$INSTALL_DIR"
cp target/release/tpm "$INSTALL_DIR/tpm"
chmod +x "$INSTALL_DIR/tpm"

echo "Installed to ${INSTALL_DIR}/tpm"

# Install vTPM component if available
TPM_DATA_DIR="${HOME}/.local/share/tpm"
mkdir -p "$TPM_DATA_DIR"
VTPM_SOURCES=(
    "../libtpms-wasm/dist/tpm-ephemeral.component.wasm"
    "${HOME}/git/libtpms-wasm/dist/tpm-ephemeral.component.wasm"
)
for src in "${VTPM_SOURCES[@]}"; do
    if [ -f "$src" ]; then
        cp "$src" "${TPM_DATA_DIR}/tpm-ephemeral.component.wasm"
        echo "vTPM component installed to ${TPM_DATA_DIR}/"
        break
    fi
done

# Install shell completions
SHELL_NAME="$(basename "$SHELL")"
case "$SHELL_NAME" in
    zsh)
        mkdir -p "${HOME}/.zsh/completions"
        "$INSTALL_DIR/tpm" completions zsh > "${HOME}/.zsh/completions/_tpm"
        echo "Zsh completions installed to ~/.zsh/completions/_tpm"
        if ! grep -q 'fpath.*zsh/completions' "${HOME}/.zshrc" 2>/dev/null; then
            echo 'fpath=(~/.zsh/completions $fpath)' >> "${HOME}/.zshrc"
            echo "Added completions dir to ~/.zshrc"
        fi
        ;;
    bash)
        mkdir -p "${HOME}/.local/share/bash-completion/completions"
        "$INSTALL_DIR/tpm" completions bash > "${HOME}/.local/share/bash-completion/completions/tpm"
        echo "Bash completions installed"
        ;;
    fish)
        mkdir -p "${HOME}/.config/fish/completions"
        "$INSTALL_DIR/tpm" completions fish > "${HOME}/.config/fish/completions/tpm.fish"
        echo "Fish completions installed"
        ;;
    *)
        echo "Run 'tpm completions $SHELL_NAME' to generate completions manually"
        ;;
esac

# Check PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    echo "Add to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo ""
echo "Run: tpm --help"
echo "Restart your shell for completions to take effect."
