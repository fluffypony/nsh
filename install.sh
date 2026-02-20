#!/usr/bin/env bash
set -euo pipefail

REPO="fluffypony/nsh"
INSTALL_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
SUPPORTED_PREBUILT_TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "i686-unknown-freebsd"
    "x86_64-unknown-freebsd"
    "i686-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "riscv64gc-unknown-linux-gnu"
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-msvc"
    "x86_64-pc-windows-gnu"
)

BOLD='\033[1m' DIM='\033[2m' GREEN='\033[32m' CYAN='\033[36m'
YELLOW='\033[33m' RED='\033[31m' RESET='\033[0m'

info()  { printf "${CYAN}▸${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}!${RESET} %s\n" "$*"; }
error() { printf "${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }

# ── Detect platform ─────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

IS_WSL=0
if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=1
    info "Detected WSL (Windows Subsystem for Linux)"
fi

case "$OS" in
    Linux)  PLATFORM="unknown-linux-gnu" ;;
    Darwin) PLATFORM="apple-darwin" ;;
    FreeBSD) PLATFORM="unknown-freebsd" ;;
    MINGW*|MSYS*|CYGWIN*)
        echo ""
        echo "Native Windows/MSYS2/Cygwin detected."
        echo "For the full nsh experience (shell wrapping), please install inside WSL:"
        echo "  wsl --install"
        echo "  # Then inside WSL: curl -fsSL https://... | sh"
        echo ""
        echo "Attempting source build for experimental native support (query/chat only)..."
        PLATFORM="pc-windows-gnu"
        ;;
    *)      error "Unsupported OS: $OS. nsh requires Linux, macOS, or FreeBSD." ;;
esac

case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    i386|i486|i586|i686|x86) ARCH="i686" ;;
    aarch64|arm64)  ARCH="aarch64" ;;
    riscv64|riscv64gc) ARCH="riscv64gc" ;;
    *)              error "Unsupported architecture: $ARCH" ;;
esac

TARGET="${ARCH}-${PLATFORM}"
info "Detected: $OS $ARCH"

has_prebuilt_target() {
    local target="$1"
    for t in "${SUPPORTED_PREBUILT_TARGETS[@]}"; do
        if [[ "$t" == "$target" ]]; then
            return 0
        fi
    done
    return 1
}

# ── Try pre-built binary first ──────────────────────────
install_from_release() {
    if ! has_prebuilt_target "$TARGET"; then
        return 1
    fi

    info "Checking for pre-built release..."
    local LATEST
    LATEST="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')" || return 1

    [[ -z "$LATEST" ]] && return 1

    local archive_ext="tar.gz"
    if [[ "$TARGET" == *windows* ]]; then
        archive_ext="zip"
    fi
    local URL="https://github.com/$REPO/releases/download/${LATEST}/nsh-${TARGET}.${archive_ext}"
    info "Downloading nsh $LATEST for $TARGET..."

    local TMP
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' RETURN

    if curl -fsSL "$URL" -o "$TMP/nsh_archive" 2>/dev/null; then
        # Compute SHA256 of downloaded archive
        local actual_sha=""
        if command -v sha256sum &>/dev/null; then
            actual_sha="$(sha256sum "$TMP/nsh_archive" | awk '{print $1}')"
        elif command -v shasum &>/dev/null; then
            actual_sha="$(shasum -a 256 "$TMP/nsh_archive" | awk '{print $1}')"
        fi

        # GitHub checksum verification
        local SHA_URL="https://github.com/$REPO/releases/download/${LATEST}/nsh-${TARGET}.${archive_ext}.sha256"
        local expected_sha=""
        if curl -fsSL "$SHA_URL" -o "$TMP/nsh.sha256" 2>/dev/null; then
            expected_sha="$(awk '{print $1}' "$TMP/nsh.sha256")"
        fi

        if [[ -n "$expected_sha" && -n "$actual_sha" ]]; then
            if [[ "$actual_sha" != "$expected_sha" ]]; then
                error "Checksum verification failed! Expected: $expected_sha Got: $actual_sha"
            fi
            ok "Checksum verified"
        elif [[ -n "$expected_sha" ]]; then
            warn "No sha256sum or shasum available, skipping checksum verification"
        else
            warn "No checksum file available, skipping verification"
        fi

        if [[ "$archive_ext" == "zip" ]]; then
            unzip -oq "$TMP/nsh_archive" -d "$TMP"
        else
            tar xzf "$TMP/nsh_archive" -C "$TMP"
        fi

        # Compute SHA256 of extracted binary (used by DNS TXT update records)
        local binary_sha=""
        if [[ -f "$TMP/nsh" || -f "$TMP/nsh.exe" ]]; then
            local extracted_bin="$TMP/nsh"
            [[ -f "$TMP/nsh.exe" ]] && extracted_bin="$TMP/nsh.exe"
            if command -v sha256sum &>/dev/null; then
                binary_sha="$(sha256sum "$extracted_bin" | awk '{print $1}')"
            elif command -v shasum &>/dev/null; then
                binary_sha="$(shasum -a 256 "$extracted_bin" | awk '{print $1}')"
            fi
        fi

        # DNS TXT cross-check
        local dns_verify_sha=""
        if command -v dig &>/dev/null; then
            local dns_records
            dns_records="$(dig +short TXT update.nsh.tools 2>/dev/null | tr -d '"')"
            dns_verify_sha="$(echo "$dns_records" | grep "^${LATEST#v}:${TARGET}:" | head -1 | cut -d: -f3)"
        fi
        if [[ -n "$dns_verify_sha" && -n "$binary_sha" ]]; then
            if [[ "$binary_sha" != "$dns_verify_sha" ]]; then
                error "DNS verification failed! Extracted binary SHA does not match DNS TXT record."
            fi
            ok "DNS verified"
        elif [[ -n "$dns_verify_sha" ]]; then
            warn "DNS record found but no sha256 tool available, skipping DNS verification"
        elif [[ -n "$expected_sha" ]]; then
            ok "GitHub checksum verified (DNS unavailable)"
        else
            warn "No verification available, proceeding with unverified binary"
        fi

        mkdir -p "$INSTALL_DIR"
        if [[ "$TARGET" == *windows* ]]; then
            install -m 755 "$TMP/nsh.exe" "$INSTALL_DIR/nsh.exe"
        else
            install -m 755 "$TMP/nsh" "$INSTALL_DIR/nsh"
        fi
        return 0
    fi
    return 1
}

install_from_source() {
    if ! command -v cargo &>/dev/null; then
        info "Cargo not found. Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        source "${CARGO_HOME:-$HOME/.cargo}/env"
    fi

    local rust_ver
    rust_ver="$(rustc --version | awk '{print $2}')"
    info "Rust $rust_ver found"

    info "Building nsh from source (this may take a minute)..."
    local TMP
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' RETURN

    if command -v git &>/dev/null; then
        git clone --depth 1 "https://github.com/${REPO}.git" "$TMP/nsh" 2>&1 | tail -1
    else
        curl -fsSL "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" \
            | tar xz -C "$TMP"
        mv "$TMP"/nsh-* "$TMP/nsh"
    fi

    cargo install --path "$TMP/nsh" --locked 2>&1 | tail -5
}

# Try release binary first, fall back to source
if ! install_from_release; then
    warn "No pre-built binary available for $TARGET."
    if [[ -t 0 ]]; then
        printf "  Build from source? This requires Rust and may take a few minutes. [y/N] "
        read -r ans
        if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
            error "Installation aborted. Pre-built binaries are available for: ${SUPPORTED_PREBUILT_TARGETS[*]}"
        fi
    fi
    install_from_source
fi

# ── Verify ──────────────────────────────────────────────
if ! command -v nsh &>/dev/null; then
    if [[ -x "$INSTALL_DIR/nsh" ]]; then
        export PATH="$INSTALL_DIR:$PATH"
    else
        error "Installation failed — nsh binary not found"
    fi
fi

ok "nsh installed at $(command -v nsh)"

# ── Config ──────────────────────────────────────────────
NSH_DIR="$HOME/.nsh"
CONFIG_FILE="$NSH_DIR/config.toml"
mkdir -p "$NSH_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
    api_key="${OPENROUTER_API_KEY:-}"
    if [[ -z "$api_key" ]] && [[ -t 0 ]]; then
        echo ""
        info "nsh needs an LLM provider API key."
        echo "  Get an OpenRouter key at: https://openrouter.ai/keys"
        echo ""
        printf "  Enter your API key (or press Enter to skip): "
        read -r api_key
    fi

    PROVIDER="openrouter"
    MODEL="google/gemini-2.5-flash"
    if [[ "$api_key" == sk-ant-* ]]; then
        PROVIDER="anthropic"
        MODEL="claude-sonnet-4-20250514"
    elif [[ "$api_key" == sk-* ]] && [[ "$api_key" != sk-or-* ]]; then
        PROVIDER="openai"
        MODEL="gpt-4.1-nano"
    fi

    if [[ -n "$api_key" ]]; then
        cat > "$CONFIG_FILE" <<EOF
[provider]
default = "$PROVIDER"
model = "$MODEL"

[provider.$PROVIDER]
api_key = "$api_key"
EOF
    else
        cat > "$CONFIG_FILE" <<'EOF'
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"

[provider.openrouter]
# api_key = "sk-or-v1-..."
EOF
    fi
    chmod 600 "$CONFIG_FILE"
    ok "Created config at $CONFIG_FILE"
else
    ok "Config already exists at $CONFIG_FILE"
fi

# ── Shell integration ───────────────────────────────────
CURRENT_SHELL="$(basename "${SHELL:-bash}")"

add_shell_integration() {
    local rc_file="$1" shell_name="$2" init_line="$3"
    if [[ -f "$rc_file" ]] && grep -qF 'nsh init' "$rc_file"; then
        ok "Shell integration already present in $rc_file"
        return
    fi
    {
        echo ""
        echo "# nsh — Natural Shell (https://github.com/${REPO})"
        echo "$init_line"
    } >> "$rc_file"
    ok "Added nsh integration to $rc_file"
}

add_shell_integration_for() {
    local s="$1"
    case "$s" in
        zsh)
            add_shell_integration "$HOME/.zshrc" "zsh" \
                'eval "$(nsh init zsh)"'
            ;;
        bash)
            local RC="$HOME/.bashrc"
            [[ "$OS" == "Darwin" && -f "$HOME/.bash_profile" && ! -f "$RC" ]] && RC="$HOME/.bash_profile"
            add_shell_integration "$RC" "bash" \
                'eval "$(nsh init bash)"'
            ;;
        fish)
            local FISH_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fish"
            mkdir -p "$FISH_DIR/conf.d"
            if [[ ! -f "$FISH_DIR/conf.d/nsh.fish" ]]; then
                cat > "$FISH_DIR/conf.d/nsh.fish" <<'FISHCONF'
# nsh — Natural Shell integration
nsh init fish | source
FISHCONF
                ok "Added nsh integration to $FISH_DIR/conf.d/nsh.fish"
            else
                ok "Fish integration already present"
            fi
            ;;
    esac
}

# Detect available shells
SHELLS_FOUND=()
[[ -f "$HOME/.bashrc" || -f "$HOME/.bash_profile" ]] && SHELLS_FOUND+=(bash)
[[ -f "$HOME/.zshrc" ]] && SHELLS_FOUND+=(zsh)
[[ -d "${XDG_CONFIG_HOME:-$HOME/.config}/fish" ]] && SHELLS_FOUND+=(fish)

# If current shell not in detected list, add it
found_current=false
for s in "${SHELLS_FOUND[@]}"; do
    [[ "$s" == "$CURRENT_SHELL" ]] && found_current=true
done
if ! $found_current; then
    SHELLS_FOUND+=("$CURRENT_SHELL")
fi

if (( ${#SHELLS_FOUND[@]} > 1 )); then
    echo ""
    echo "Multiple shells detected: ${SHELLS_FOUND[*]}"
    for s in "${SHELLS_FOUND[@]}"; do
        if [[ "$s" == "$CURRENT_SHELL" ]]; then
            add_shell_integration_for "$s"
        else
            printf "  Add nsh to %s? [Y/n] " "$s"
            if [[ -t 0 ]]; then
                read -r ans
                [[ "$ans" != "n" && "$ans" != "N" ]] && add_shell_integration_for "$s"
            else
                add_shell_integration_for "$s"
            fi
        fi
    done
elif (( ${#SHELLS_FOUND[@]} == 1 )); then
    add_shell_integration_for "${SHELLS_FOUND[0]}"
else
    warn "No supported shell detected. Add manually:"
    warn '  eval "$(nsh init bash)"   # or zsh/fish'
fi

echo ""

# Run autoconfigure if no config exists
if [ ! -f "$HOME/.nsh/config.toml" ]; then
    info "Running initial configuration..."
    if "$INSTALL_DIR/nsh" autoconfigure; then
        :
    else
        warn "Auto-configuration skipped. Run 'nsh autoconfigure' to configure later."
    fi
    echo ""
fi

ok "nsh installed successfully!"
echo ""
echo "  Start a new shell, then try:"
echo -e "    ${DIM}?${RESET} what is my ip address"
echo ""
