#!/bin/bash
# =============================================================================
# Parameter Extraction & GF Pattern Filtering
#
# Extracts URLs with parameters from crawled URLs, then filters them
# through gf patterns to find potential vulnerability vectors.
#
# Usage:
#   ./tools/param_extract.sh <domain>
#   ./tools/param_extract.sh <domain> --crawled <crawledurls.txt>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET=""; CRAWLED=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --crawled) shift; CRAWLED="${1:-}" ;;
    -h|--help) sed -n '6,10p' "$0"; exit 0 ;;
    *) TARGET="$1" ;;
  esac
  shift
done

[ -z "$TARGET" ] && { echo "Usage: $0 <domain> [--crawled <file>]" >&2; exit 1; }
[ -z "$CRAWLED" ] && CRAWLED="$BASE_DIR/recon/$TARGET/crawl/crawledurls.txt"

OUT_DIR="$BASE_DIR/recon/$TARGET/params"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

if [ ! -f "$CRAWLED" ] || [ ! -s "$CRAWLED" ]; then
  log_err "crawledurls.txt not found: $CRAWLED"
  log_info "Run web_crawl.sh first or provide --crawled <file>"
  exit 1
fi

# ── Step 1: Extract param URLs ──────────────────────────────────────
log_info "Extracting URLs with parameters ..."
grep "?" "$CRAWLED" | sort -u > "$OUT_DIR/paramurls.txt"
NPARAM=$(wc -l < "$OUT_DIR/paramurls.txt" | tr -d ' ')
log_ok "paramurls.txt: $NPARAM URLs with parameters"

# ── Step 2: Ensure gf is installed ──────────────────────────────────
if ! command -v gf &>/dev/null; then
  log_info "Installing gf ..."
  go install github.com/tomnomnom/gf@latest 2>/dev/null
  log_ok "gf installed"
fi

# ── Step 3: Setup gf patterns from wordlists ────────────────────────
GF_DIR="$HOME/.gf"
PATTERNS_SRC="$BASE_DIR/wordlists/gf-patterns"

if [ -d "$PATTERNS_SRC" ] && [ -z "$(ls -A "$GF_DIR" 2>/dev/null)" ]; then
  log_info "Copying gf patterns from wordlists ..."
  mkdir -p "$GF_DIR"
  cp "$PATTERNS_SRC"/*.json "$GF_DIR/" 2>/dev/null
fi

# ── Step 4: Filter by gf patterns ───────────────────────────────────
CLASSES=("xss" "sqli" "ssrf" "ssti" "lfi" "redirect" "idor" "rce" "rfi" "cmdi" "xxe" "debug_logic" "interestingparams")
TOTAL=0

for cls in "${CLASSES[@]}"; do
  gf "$cls" "$OUT_DIR/paramurls.txt" 2>/dev/null | sort -u > "$OUT_DIR/gf_$cls.txt"
  N=$(wc -l < "$OUT_DIR/gf_$cls.txt" | tr -d ' ')
  if [ "$N" -gt 0 ]; then
    log_ok "gf_$cls.txt: $N candidates"
    TOTAL=$((TOTAL + N))
  fi
done

# ── Step 5: Summary ─────────────────────────────────────────────────
log_ok "Done. Results in $OUT_DIR/"
log_ok "  paramurls.txt     — $NPARAM URLs with params"
log_ok "  gf_*.txt           — $TOTAL total candidates across ${#CLASSES[@]} classes"
echo ""
for cls in "${CLASSES[@]}"; do
  N=$(wc -l < "$OUT_DIR/gf_$cls.txt" 2>/dev/null | tr -d ' ')
  [ "$N" -gt 0 ] && echo "    $(printf '%-20s' "$cls") $N candidate(s)"
done
