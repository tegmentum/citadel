#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.local/bin"

echo "Building tpm (release)..."
cargo build --release -p tpm 2>&1 | tail -1

mkdir -p "$INSTALL_DIR"
cp target/release/tpm "$INSTALL_DIR/tpm"
chmod +x "$INSTALL_DIR/tpm"

echo "Installed to ${INSTALL_DIR}/tpm"

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
