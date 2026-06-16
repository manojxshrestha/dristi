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
BASE_URL="https://$TARGET"
if [ "${2:-}" = "--url" ] && [ -n "${3:-}" ]; then
  BASE_URL="$3"
fi
BASE_URL="${BASE_URL%/}"

: "${RECON_BASE:?RECON_BASE not set}"

OUT_DIR="${RECON_BASE}/$TARGET/directories"
mkdir -p "$OUT_DIR"

WORDLIST_DIR="$BASE_DIR/wordlists/content"
mkdir -p "$WORDLIST_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Download wordlist ───────────────────────────────────────────────
WORDLIST="$WORDLIST_DIR/raft-medium-directories.txt"
if [ ! -f "$WORDLIST" ]; then
  log_info "Downloading directory wordlist from manojxshrestha/wordlists..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/main/Web-Content/raft-medium-directories.txt" -O "$WORDLIST"
  log_ok "Downloaded $(wc -l < "$WORDLIST" | tr -d ' ') entries"
fi

# ── Ensure ffuf is installed ────────────────────────────────────────
if ! command -v ffuf &>/dev/null; then
  log_warn "ffuf not found — skipping dir bruteforce (install: go install github.com/ffuf/ffuf/v2@latest)"
  log_info "Use katana/gospider crawl output + hunt agents instead"
  exit 0
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

# ── Run ffuf directory bruteforce ───────────────────────────────────
log_info "Directory bruteforcing $BASE_URL ..."
log_info "  Wordlist: $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"

ffuf \
  -u "$BASE_URL/FUZZ" \
  -w "$WORDLIST" \
  -ac \
  -o "$OUT_DIR/ffuf_results.json" \
  -of json \
  -v \
  2>/dev/null || true

# ── Parse results ───────────────────────────────────────────────────
if [ -s "$OUT_DIR/ffuf_results.json" ]; then
  python3 <<EOF
import json

with open("$OUT_DIR/ffuf_results.json") as f:
    data = json.load(f)

results = data.get("results", [])
if results:
    print(f"Found {len(results)} paths:")
    for r in sorted(results, key=lambda x: x.get("status", 0)):
        word = r.get("input", {}).get("FUZZ", "?")
        print(f"  /{word} -> {r.get('status')} ({r.get('length')} bytes)")
else:
    print("No paths discovered.")
EOF
else
  log_warn "No results from ffuf"
fi

log_ok "Done. Results in $OUT_DIR/"
