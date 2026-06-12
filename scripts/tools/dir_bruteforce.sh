#!/bin/bash
# =============================================================================
# Directory Bruteforcing — ffuf-based content discovery
#
# Discovers hidden directories, files, and endpoints on a target.
# Also checks common info-disclosure paths (robots.txt, sitemap.xml, etc.).
#
# Usage:
#   ./tools/dir_bruteforce.sh <domain>
#   ./tools/dir_bruteforce.sh <domain> --url https://target.com
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--url <base-url>]}"
BASE_URL="${3:-https://$TARGET}"

OUT_DIR="$BASE_DIR/recon/$TARGET/directories"
mkdir -p "$OUT_DIR"

WORDLIST_DIR="$BASE_DIR/wordlists/content"
mkdir -p "$WORDLIST_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Download wordlist ───────────────────────────────────────────────
WORDLIST="$WORDLIST_DIR/raft-medium-directories.txt"
if [ ! -f "$WORDLIST" ]; then
  log_info "Downloading directory wordlist from manojxshrestha/wordlists..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/refs/heads/main/Web-Content/raft-medium-directories.txt" -O "$WORDLIST"
  log_ok "Downloaded $(wc -l < "$WORDLIST" | tr -d ' ') entries"
fi

# ── Ensure ffuf is installed ────────────────────────────────────────
if ! command -v ffuf &>/dev/null; then
  log_err "ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest"
  exit 1
fi

# ── Check robots.txt, sitemap.xml, etc. ─────────────────────────────
log_info "Checking common info-disclosure paths..."
COMMON_PATHS=(
  "robots.txt"
  "sitemap.xml"
  "sitemap-index.xml"
  "sitemap_index.xml"
  "sitemapindex.xml"
  "sitemap1.xml"
  "sitemap-main.xml"
)

for path in "${COMMON_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/$path" 2>/dev/null)
  if [ "$STATUS" != "404" ]; then
    log_ok "  $BASE_URL/$path -> $STATUS"
    echo "$BASE_URL/$path -> $STATUS" >> "$OUT_DIR/common_paths.txt"
  else
    log_info "  $BASE_URL/$path -> $STATUS"
  fi
done

# ── Get baseline Content-Length for filtering ───────────────────────
RAND_PATH="asdkfl3$RANDOM$RANDOM"
BASELINE=$(curl -s -I "$BASE_URL/$RAND_PATH" 2>/dev/null \
  | grep -i "Content-Length:" \
  | awk '{print $2}' \
  | tr -d '\r')

BASELINE="${BASELINE:-0}"
log_info "Baseline Content-Length: $BASELINE (non-existent path: /$RAND_PATH)"

# ── Run ffuf directory bruteforce ───────────────────────────────────
log_info "Directory bruteforcing $BASE_URL ..."
log_info "  Wordlist: $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"
log_info "  Filter: -fc 404,403 -fs 0,$BASELINE"

ffuf -u "$BASE_URL/FUZZ" \
     -w "$WORDLIST" \
     -fc 404,403 \
     -fs "0,$BASELINE" \
     -ac \
     -o "$OUT_DIR/ffuf_results.json" \
     -of json \
     -v 2>/dev/null

# ── Parse results ───────────────────────────────────────────────────
if [ -s "$OUT_DIR/ffuf_results.json" ]; then
  python3 -c "
import json
with open('$OUT_DIR/ffuf_results.json') as f:
    data = json.load(f)
results = data.get('results', [])
if results:
    print(f'Found {len(results)} paths:')
    for r in sorted(results, key=lambda x: x.get('status', 0)):
        print(f\"  /{r.get('input', {}).get('FUZZ', '?')} -> {r.get('status')} ({r.get('length')} bytes)\")
else:
    print('No paths discovered.')
" | tee "$OUT_DIR/discovered_paths.txt"
else
  log_warn "No results from ffuf"
fi

log_ok "Done. Results in $OUT_DIR/"
