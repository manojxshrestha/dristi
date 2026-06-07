#!/bin/bash
# =============================================================================
# Subdomain Enumeration — passive + live probe
#
# Uses subfinder + assetfinder + findomain for passive discovery,
# then httpx to filter live domains. No external repo dependency.
#
# Usage:
#   ./tools/subdomain_enum.sh <domain>
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain>}"

OUT_DIR="$BASE_DIR/recon/$TARGET/subdomains"
TMP_DIR="$OUT_DIR/.tmp"
mkdir -p "$TMP_DIR" "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Ensure tools are installed ──────────────────────────────────────
# Ensure GOPATH/bin is in PATH
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  export PATH="$PATH:$HOME/go/bin"
fi

for tool in subfinder assetfinder httpx; do
  if ! command -v "$tool" &>/dev/null; then
    log_info "Installing $tool ..."
    case "$tool" in
      subfinder)  GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
      assetfinder) GO111MODULE=on go install github.com/tomnomnom/assetfinder@latest ;;
      httpx)      GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
    esac
    log_ok "$tool installed"
  fi
done

if ! command -v findomain &>/dev/null; then
  log_info "Installing findomain ..."
  wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" -O /tmp/findomain-linux.zip
  unzip -q -o /tmp/findomain-linux.zip -d /tmp/findomain 2>/dev/null
  chmod +x /tmp/findomain/findomain
  sudo mv /tmp/findomain/findomain /usr/bin/findomain
  rm -rf /tmp/findomain-linux.zip /tmp/findomain
  log_ok "findomain installed"
fi

# ── Step 1: Passive subdomain enumeration ───────────────────────────
log_info "Running subfinder ..."
subfinder -d "$TARGET" -silent 2>/dev/null | sort -u > "$TMP_DIR/subfinder.txt"
log_ok "  subfinder: $(wc -l < "$TMP_DIR/subfinder.txt" | tr -d ' ') subs"

log_info "Running assetfinder ..."
assetfinder --subs-only "$TARGET" 2>/dev/null | sort -u > "$TMP_DIR/assetfinder.txt"
log_ok "  assetfinder: $(wc -l < "$TMP_DIR/assetfinder.txt" | tr -d ' ') subs"

log_info "Running findomain ..."
findomain -t "$TARGET" -q 2>/dev/null | sort -u > "$TMP_DIR/findomain.txt"
log_ok "  findomain: $(wc -l < "$TMP_DIR/findomain.txt" | tr -d ' ') subs"

# ── Step 2: Merge ───────────────────────────────────────────────────
cat "$TMP_DIR/subfinder.txt" "$TMP_DIR/assetfinder.txt" "$TMP_DIR/findomain.txt" \
  | sort -u > "$OUT_DIR/all_subdomains.txt"
TOTAL=$(wc -l < "$OUT_DIR/all_subdomains.txt" | tr -d ' ')
log_ok "Total unique subdomains: $TOTAL"

# ── Step 3: Live probe with httpx ───────────────────────────────────
log_info "Probing live hosts with httpx ..."
httpx -l "$OUT_DIR/all_subdomains.txt" \
      -silent \
      -o "$OUT_DIR/live_domains.txt" \
      2>/dev/null

LIVE=$(wc -l < "$OUT_DIR/live_domains.txt" | tr -d ' ')
log_ok "Live hosts: $LIVE"

# ── Step 4: HTTPS URLs ──────────────────────────────────────────────
if [ "$LIVE" -gt 0 ]; then
  httpx -l "$OUT_DIR/live_domains.txt" \
        -silent \
        -o "$OUT_DIR/live_urls.txt" \
        2>/dev/null
  log_ok "HTTPS URLs saved to $OUT_DIR/live_urls.txt"
fi

# ── Cleanup ─────────────────────────────────────────────────────────
rm -rf "$TMP_DIR"

log_ok "Done. Results in $OUT_DIR/"
log_ok "  all_subdomains.txt — $TOTAL subs"
log_ok "  live_domains.txt   — $LIVE live"
