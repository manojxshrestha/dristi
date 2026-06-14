#!/bin/bash
# =============================================================================
# Subdomain Enumeration — passive discovery + DNS resolution + live probe
#
# Chain: subfinder + assetfinder + findomain → dnsx → httpx (with tech-detect)
# Outputs:
#   all_subdomains.txt — all unique domains from passive sources
#   alive-domains.txt  — clean domain names (resolved + alive)
#   https-subs.txt     — full HTTPS URLs for downstream tools
#   live_domains.txt   — httpx raw output (status, tech, title, server)
#   live_urls.txt      — HTTPS URLs (for web_crawl.sh autodetect)
#
# Usage:
#   ./tools/subdomain_enum.sh <domain>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain>}"

OUT_DIR="$BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subdomains"
TMP_DIR="$OUT_DIR/.tmp"
mkdir -p "$TMP_DIR" "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  export PATH="$PATH:$HOME/go/bin"
fi

# ── Ensure tools are installed ──────────────────────────────────────
for tool in subfinder assetfinder httpx dnsx jq; do
  if ! command -v "$tool" &>/dev/null; then
    log_info "Installing $tool ..."
    case "$tool" in
      subfinder)  GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
      assetfinder) GO111MODULE=on go install github.com/tomnomnom/assetfinder@latest ;;
      httpx)      GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
      dnsx)       GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest ;;
    esac
    log_ok "$tool installed"
  fi
done

if ! command -v findomain &>/dev/null; then
  log_info "Installing findomain ..."
  command -v unzip &>/dev/null || { log_err "unzip required"; exit 1; }
  wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" -O /tmp/findomain-linux.zip
  unzip -q -o /tmp/findomain-linux.zip -d /tmp/findomain 2>/dev/null
  chmod +x /tmp/findomain/findomain
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  mv /tmp/findomain/findomain "$INSTALL_DIR/findomain"
  export PATH="$INSTALL_DIR:$PATH"
  rm -rf /tmp/findomain-linux.zip /tmp/findomain
  log_ok "findomain installed"
fi

# ── Step 1: Passive subdomain enumeration ───────────────────────────
log_info "Running subfinder ..."
subfinder -d "$TARGET" -all -silent 2>/dev/null | sort -u > "$TMP_DIR/subfinder.txt"
log_ok "  subfinder: $(wc -l < "$TMP_DIR/subfinder.txt" | tr -d ' ') subs"

log_info "Running assetfinder ..."
assetfinder --subs-only "$TARGET" 2>/dev/null | sort -u > "$TMP_DIR/assetfinder.txt"
log_ok "  assetfinder: $(wc -l < "$TMP_DIR/assetfinder.txt" | tr -d ' ') subs"

log_info "Running findomain ..."
findomain -t "$TARGET" -q 2>/dev/null | sort -u > "$TMP_DIR/findomain.txt"
log_ok "  findomain: $(wc -l < "$TMP_DIR/findomain.txt" | tr -d ' ') subs"

log_info "Running crt.sh ..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' \
  | tr '\r' '\n' \
  | grep -E "\.${TARGET}$" \
  | sort -u > "$TMP_DIR/crtsh.txt"
log_ok "  crt.sh: $(wc -l < "$TMP_DIR/crtsh.txt" | tr -d ' ') subs"

# ── Step 2: Merge ───────────────────────────────────────────────────
cat "$TMP_DIR/subfinder.txt" "$TMP_DIR/assetfinder.txt" "$TMP_DIR/findomain.txt" "$TMP_DIR/crtsh.txt" \
  | sort -u > "$OUT_DIR/all_subdomains.txt"
TOTAL=$(wc -l < "$OUT_DIR/all_subdomains.txt" | tr -d ' ')
log_ok "Total unique subdomains: $TOTAL"

# ── Step 3: DNS resolution with dnsx ────────────────────────────────
log_info "Resolving subdomains with dnsx ..."
dnsx -l "$OUT_DIR/all_subdomains.txt" -silent -a 2>/dev/null \
  | awk '{print $1}' | sort -u > "$TMP_DIR/resolved.txt"
RESOLVED=$(wc -l < "$TMP_DIR/resolved.txt" | tr -d ' ')
log_ok "  Resolved: $RESOLVED"

if [ "$RESOLVED" -eq 0 ]; then
  log_warn "No resolved subdomains. Skipping httpx probe."
  rm -rf "$TMP_DIR"
  exit 0
fi

# ── Step 4: Live probe with httpx (status + tech-detection) ─────────
log_info "Probing live hosts with httpx ..."
httpx -l "$TMP_DIR/resolved.txt" \
      -ports 80,443 \
      -status-code \
      -title \
      -tech-detect \
      -web-server \
      -content-length \
      -threads 100 \
      -silent \
      -o "$OUT_DIR/live_domains.txt" \
      2>/dev/null

LIVE=$(wc -l < "$OUT_DIR/live_domains.txt" | tr -d ' ')
log_ok "  Live hosts: $LIVE"

# ── Step 5: Extract clean domain lists for downstream tools ─────────
NDOMAINS=0
NURLS=0
if [ "$LIVE" -gt 0 ]; then
  # All live URLs (protocol + host)
  awk '{print $1}' "$OUT_DIR/live_domains.txt" | sort -u \
    > "$OUT_DIR/live_urls.txt"

  # Clean domain names (strip protocol, strip path)
  sed 's|https\?://||' "$OUT_DIR/live_urls.txt" \
    | sed 's|/.*||' | sort -u \
    > "$OUT_DIR/alive-domains.txt"

  # HTTPS-only URLs for tools that need it
  grep "^https://" "$OUT_DIR/live_urls.txt" \
    > "$OUT_DIR/https-subs.txt"

  NDOMAINS=$(wc -l < "$OUT_DIR/alive-domains.txt" | tr -d ' ')
  NURLS=$(wc -l < "$OUT_DIR/https-subs.txt" | tr -d ' ')
  log_ok "  Clean domains: $NDOMAINS"
  log_ok "  HTTPS URLs: $NURLS"
fi

# ── Cleanup ─────────────────────────────────────────────────────────
rm -rf "$TMP_DIR"

log_ok "Done. Results in $OUT_DIR/"
log_ok "  all_subdomains.txt — $TOTAL subs (raw)"
if [ "$LIVE" -gt 0 ]; then
  log_ok "  live_urls.txt      — $NURLS live URLs (protocol+host)"
  log_ok "  alive-domains.txt  — $NDOMAINS clean domains"
  log_ok "  https-subs.txt     — HTTPS-only URLs"
  log_ok "  live_domains.txt   — $LIVE httpx output (tech + status)"
else
  log_ok "  No live hosts found."
fi
