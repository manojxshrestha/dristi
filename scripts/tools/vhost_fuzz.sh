#!/bin/bash
# =============================================================================
# VHost Fuzzing — ffuf-based virtual host discovery
#
# Finds hidden vhosts that don't have DNS records but still respond
# to the right Host header on the same IP.
#
# Usage:
#   ./tools/vhost_fuzz.sh <domain> [--url <base-url>]
#
# Examples:
#   ./tools/vhost_fuzz.sh humo.be
#   ./tools/vhost_fuzz.sh humo.be --url http://justeattakeaway.com
# =============================================================================

set -euo pipefail

ENV_FILE="$(dirname "$0")/_env.sh"
if [ -f "$ENV_FILE" ]; then
  source "$ENV_FILE"
else
  echo "[-] _env.sh not found at $ENV_FILE" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  echo "Usage: $0 <domain> [--url <base-url>]"
  exit 0
fi

TARGET="$1"
BASE_URL="http://$TARGET"
if [ "${2:-}" = "--url" ] && [ -n "${3:-}" ]; then
  BASE_URL="$3"
fi
BASE_URL="${BASE_URL%/}"

: "${RECON_BASE:?RECON_BASE not set}"

OUT_DIR="${RECON_BASE}/$TARGET/vhost"
mkdir -p "$OUT_DIR"

WORDLIST_DIR="$BASE_DIR/wordlists/vhost"
mkdir -p "$WORDLIST_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Download wordlist ───────────────────────────────────────────────
WORDLIST="$WORDLIST_DIR/common.txt"
if [ ! -f "$WORDLIST" ]; then
  log_info "Downloading vhost wordlist from manojxshrestha/wordlists..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/main/common.txt" -O "$WORDLIST"
  log_ok "Downloaded $(wc -l < "$WORDLIST" | tr -d ' ') entries"
fi

# ── Ensure ffuf is installed ────────────────────────────────────────
if ! command -v ffuf &>/dev/null; then
  log_warn "ffuf not found — skipping vhost fuzzing (install: go install github.com/ffuf/ffuf/v2@latest)"
  log_info "Use manual Host header testing instead"
  exit 0
fi

# ── Run ffuf vhost fuzzing ──────────────────────────────────────────
log_info "Fuzzing vhosts on $TARGET via $BASE_URL..."
log_info "  Wordlist: $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"

ffuf \
  -w "$WORDLIST:FUZZ" \
  -u "$BASE_URL/" \
  -H "Host: FUZZ.$TARGET" \
  -ac \
  -o "$OUT_DIR/vhost_results.json" \
  -of json \
  -v \
  2>/dev/null || true

# ── Parse results ───────────────────────────────────────────────────
if [ -s "$OUT_DIR/vhost_results.json" ]; then
  python3 <<EOF
import json

with open("$OUT_DIR/vhost_results.json") as f:
    data = json.load(f)

results = data.get("results", [])
if results:
    print(f"Found {len(results)} vhosts:")
    for r in results:
        word = r.get("input", {}).get("FUZZ", "?")
        print(f"  {word}.$TARGET -> {r.get('status')} ({r.get('length')} bytes)")
else:
    print("No vhosts found.")
EOF
else
  log_warn "No results from ffuf"
fi

log_ok "Done. Results in $OUT_DIR/"
