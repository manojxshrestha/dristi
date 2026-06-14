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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--url <base-url>]}"
BASE_URL="${3:-http://$TARGET}"

OUT_DIR="$BASE_DIR/recon/$TARGET/vhost"
mkdir -p "$OUT_DIR"

WORDLIST_DIR="$BASE_DIR/wordlists/vhost"
mkdir -p "$WORDLIST_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Download wordlist ───────────────────────────────────────────────
WORDLIST="$WORDLIST_DIR/common.txt"
if [ ! -f "$WORDLIST" ]; then
  log_info "Downloading vhost wordlist from manojxshrestha/wordlists..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/refs/heads/main/common.txt" -O "$WORDLIST"
  log_ok "Downloaded $(wc -l < "$WORDLIST" | tr -d ' ') entries"
fi

# ── Ensure ffuf is installed ────────────────────────────────────────
if ! command -v ffuf &>/dev/null; then
  log_err "ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest"
  exit 1
fi

# ── Get baseline Content-Length ─────────────────────────────────────
INVALID="defnotvalid-$RANDOM.$TARGET"
BASELINE=$(curl -s -I "$BASE_URL" -H "Host: $INVALID" 2>/dev/null \
  | grep -i "Content-Length:" \
  | awk '{print $2}' \
  | tr -d '\r')

if [ -z "$BASELINE" ]; then
  log_warn "Could not determine baseline Content-Length. Using 0."
  BASELINE=0
fi
log_info "Baseline Content-Length: $BASELINE (invalid vhost: $INVALID)"

# ── Run ffuf vhost fuzzing ──────────────────────────────────────────
log_info "Fuzzing vhosts on $TARGET via $BASE_URL..."
log_info "  Wordlist: $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"
log_info "  Filter: -fs $BASELINE -fc 403"

ffuf -w "$WORDLIST:FUZZ" \
     -u "$BASE_URL/" \
     -H "Host: FUZZ.$TARGET" \
     -fs "$BASELINE" \
     -fc 403 \
     -ac \
     -o "$OUT_DIR/vhost_results.json" \
     -of json \
     -v 2>/dev/null

# ── Parse results ───────────────────────────────────────────────────
if [ -s "$OUT_DIR/vhost_results.json" ]; then
  python3 -c "
import json
with open('$OUT_DIR/vhost_results.json') as f:
    data = json.load(f)
results = data.get('results', [])
if results:
    print(f'Found {len(results)} vhosts:')
    for r in results:
        print(f\"  {r.get('input', {}).get('FUZZ', '?')}.$TARGET -> {r.get('status')} ({r.get('length')} bytes)\")
else:
    print('No vhosts found.')
" | tee "$OUT_DIR/vhost_found.txt"
else
  log_warn "No results from ffuf"
fi

log_ok "Done. Results in $OUT_DIR/"
