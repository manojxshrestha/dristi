#!/bin/bash
# =============================================================================
# DNS Brute-Force — puredns + massdns with curated wordlists
#
# Usage:
#   ./tools/dns_bruteforce.sh <domain>
#   ./tools/dns_bruteforce.sh <domain> --wordlist <custom.txt>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--wordlist <file>]}"
WORDLIST="${3:-}"

OUT_DIR="${RECON_OUT_DIR:-$BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-rea-group-bb-001}/recon/$TARGET}"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Prepare wordlists ──────────────────────────────────────────────
WORDLIST_DIR="$BASE_DIR/wordlists/dns"
mkdir -p "$WORDLIST_DIR"

SUB_LIST="$WORDLIST_DIR/subdomains-top1million-20000.txt"
RESOLVERS="$WORDLIST_DIR/resolvers.txt"

if [ ! -f "$SUB_LIST" ]; then
  log_info "Downloading subdomain wordlist..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/refs/heads/main/subdomains-top1million-20000.txt" -O "$SUB_LIST"
  log_ok "Downloaded $(wc -l < "$SUB_LIST" | tr -d ' ') subdomains"
fi

if [ ! -f "$RESOLVERS" ]; then
  log_info "Downloading resolvers list..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/refs/heads/main/resolvers.txt" -O "$RESOLVERS"
  log_ok "Downloaded $(wc -l < "$RESOLVERS" | tr -d ' ') resolvers"
fi

USE_LIST="${WORDLIST:-$SUB_LIST}"

# ── Ensure tools are installed ──────────────────────────────────────

if ! command -v puredns &>/dev/null; then
  log_info "Installing puredns..."
  go install github.com/d3mondev/puredns/v2@latest 2>/dev/null
fi

if ! command -v massdns &>/dev/null; then
  log_info "Compiling massdns..."
  TMPDIR=$(mktemp -d)
  git clone --depth 1 https://github.com/blechschmidt/massdns.git "$TMPDIR/massdns" 2>/dev/null
  make -C "$TMPDIR/massdns" -s 2>/dev/null
  sudo cp "$TMPDIR/massdns/bin/massdns" /usr/local/bin/ 2>/dev/null
  rm -rf "$TMPDIR"
  log_ok "massdns installed"
fi

# ── Run puredns bruteforce ──────────────────────────────────────────

log_info "Running puredns bruteforce on $TARGET..."
log_info "  Wordlist: $USE_LIST ($(wc -l < "$USE_LIST" | tr -d ' ') entries)"
log_info "  Resolvers: $RESOLVERS ($(wc -l < "$RESOLVERS" | tr -d ' ') entries)"

puredns bruteforce "$USE_LIST" "$TARGET" -r "$RESOLVERS" \
  | tee "$OUT_DIR/dns_bruteforce.txt"

COUNT=$(wc -l < "$OUT_DIR/dns_bruteforce.txt" | tr -d ' ')
log_ok "Found $COUNT resolved subdomains"
log_ok "Saved to $OUT_DIR/dns_bruteforce.txt"
