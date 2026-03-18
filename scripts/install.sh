#!/usr/bin/env bash
# ================================================================
#  ai-server-audit — One-line installer
#  Created by Turac
#  Usage:
#    curl -sSf https://raw.githubusercontent.com/YOUR_USER/ai-server-audit/main/scripts/install.sh | bash
# ================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[info]${RESET}  $*"; }
success() { echo -e "${GREEN}[ok]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET}  $*"; }
die()     { echo -e "${RED}[error]${RESET} $*" >&2; exit 1; }

echo
echo -e "${CYAN}${BOLD}  ┌──────────────────────────────────────────────────┐${RESET}"
echo -e "${CYAN}${BOLD}  │  🦀 + 🐹  AI Server Audit Installer             │${RESET}"
echo -e "${CYAN}${BOLD}  │     Rust Core + Go CLI  ·  v0.1.0               │${RESET}"
echo -e "${CYAN}${BOLD}  │     Created by Turac                            │${RESET}"
echo -e "${CYAN}${BOLD}  └──────────────────────────────────────────────────┘${RESET}"
echo

# ── Platform ─────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux*)  PLATFORM="linux"  ;;
  Darwin*) PLATFORM="darwin" ;;
  *)       die "Unsupported OS: $OS  (Windows users: please use WSL2)" ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_TAG="amd64" ;;
  aarch64|arm64) ARCH_TAG="arm64" ;;
  *)             die "Unsupported architecture: $ARCH" ;;
esac

info "Platform: ${PLATFORM}/${ARCH_TAG}"

# ── Install dir ───────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
if [[ ! -w "$INSTALL_DIR" ]]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  warn "No write access to /usr/local/bin — installing to $INSTALL_DIR"
  warn "Add to your shell config: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ── Try pre-built binary first ────────────────────────────────────
REPO="YOUR_GITHUB_USERNAME/ai-server-audit"
BINARY_URL="https://github.com/${REPO}/releases/latest/download/ai-server-audit-${PLATFORM}-${ARCH_TAG}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

DOWNLOAD_OK=false
info "Trying pre-built binary…"
if command -v curl &>/dev/null; then
  curl -fsSL "$BINARY_URL" -o "${TMP_DIR}/ai-server-audit" 2>/dev/null && DOWNLOAD_OK=true
elif command -v wget &>/dev/null; then
  wget -qO  "${TMP_DIR}/ai-server-audit" "$BINARY_URL"    2>/dev/null && DOWNLOAD_OK=true
fi

# ── Build from source if no binary ───────────────────────────────
if [[ "$DOWNLOAD_OK" == "false" ]]; then
  warn "Pre-built binary not found — building from source (this takes ~2 min)…"
  command -v git &>/dev/null || die "git is required to build from source"

  # Install Rust
  if ! command -v cargo &>/dev/null; then
    info "Installing Rust via rustup…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
  fi
  success "Rust: $(rustc --version)"

  # Install Go
  if ! command -v go &>/dev/null; then
    info "Installing Go 1.22…"
    GO_TAR="go1.22.4.${PLATFORM}-${ARCH_TAG}.tar.gz"
    curl -fsSL "https://golang.org/dl/${GO_TAR}" -o "${TMP_DIR}/${GO_TAR}"
    sudo tar -C /usr/local -xzf "${TMP_DIR}/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
  fi
  success "Go: $(go version)"

  # Clone & build
  info "Cloning repository…"
  git clone --depth=1 "https://github.com/${REPO}.git" "${TMP_DIR}/repo"
  cd "${TMP_DIR}/repo"

  info "Building Rust core…"
  cd core && cargo build --release --quiet
  success "Rust core compiled"

  info "Building Go CLI…"
  cd ../cli
  CGO_ENABLED=1 \
    CGO_LDFLAGS="-L../core/target/release -laudit_core -ldl -lpthread -lm" \
    go build -ldflags="-s -w" -o "${TMP_DIR}/ai-server-audit" .
  success "Go CLI compiled"
fi

# ── Install ───────────────────────────────────────────────────────
chmod +x "${TMP_DIR}/ai-server-audit"
install -m 755 "${TMP_DIR}/ai-server-audit" "${INSTALL_DIR}/ai-server-audit"
success "Installed → ${INSTALL_DIR}/ai-server-audit"

# ── Verify ───────────────────────────────────────────────────────
if command -v ai-server-audit &>/dev/null; then
  success "ai-server-audit is ready!"
else
  warn "Not in PATH. Add: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo
echo -e "${BOLD}  Quick start:${RESET}"
echo -e "  ${CYAN}1.${RESET} ${BOLD}ai-server-audit init${RESET}                    # create audit.json"
echo -e "  ${CYAN}2.${RESET} Edit ${BOLD}audit.json${RESET} — set your server IP & API keys"
echo -e "  ${CYAN}3.${RESET} ${BOLD}ai-server-audit run${RESET}                     # full audit"
echo -e "  ${CYAN}4.${RESET} ${BOLD}ai-server-audit ports --host 10.0.0.1${RESET}  # port scan only"
echo -e "  ${CYAN}5.${RESET} ${BOLD}ai-server-audit run --output json --report out.json${RESET}"
echo
echo -e "  ${GREEN}${BOLD}Happy auditing! 🦀🐹${RESET}"
echo
echo -e "  ${CYAN}Created by Turac${RESET}"
echo
