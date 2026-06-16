#!/bin/bash
# =============================================================================
# Cariddi Scan — secrets, info disclosure, endpoints, errors, juicy files
#
# Two-pass scan:
#   1. Full intensive scan (secrets, info, errors, extensions)
#   2. Targeted high-value path scan (.env, .git, config, etc.)
#
# Usage:
#   ./tools/cariddi_scan.sh <domain>                 # auto paths under recon/<domain>/crawl/
#   ./tools/cariddi_scan.sh <domain> <alive-file>    # custom alive domains file
#   ./tools/cariddi_scan.sh <alive-file>             # direct file path, domain from path
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET_RAW="${1:?Usage: $0 <domain> [<alive-file>]}"

if [[ "$TARGET_RAW" == -* ]]; then
  TARGET_RAW="${2:?Usage: $0 <domain> [<alive-file>]}"
  ALIVE_FILE="${3:-}"
else
  ALIVE_FILE="${2:-}"
  [[ "$ALIVE_FILE" == -* ]] && ALIVE_FILE="${3:-}"
fi

if [[ "$TARGET_RAW" == */* ]]; then
  ALIVE_FILE="$TARGET_RAW"
  TARGET=$(echo "$TARGET_RAW" | sed -n 's|.*/recon/\([^/]*\)/.*|\1|p')
  [ -z "$TARGET" ] && TARGET="target"
else
  TARGET="$TARGET_RAW"
  [ -z "$ALIVE_FILE" ] && ALIVE_FILE="${RECON_BASE}/$TARGET/subdomains/alive-domains.txt"
fi

OUT_DIR="${RECON_BASE}/$TARGET/cariddi"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

if [ ! -f "$ALIVE_FILE" ] || [ ! -s "$ALIVE_FILE" ]; then
  log_err "alive-domains.txt not found: $ALIVE_FILE"
  log_info "Run auto_recon.sh first or provide --alive <file>"
  exit 1
fi

if ! command -v cariddi &>/dev/null; then
  log_err "cariddi not found — install via: go install github.com/edoardottt/cariddi/cmd/cariddi@latest"
  exit 1
fi

# ── Clean previous run ──────────────────────────────────────────────
rm -rf "$OUT_DIR/output-cariddi"
rm -f "$OUT_DIR/cariddi.txt" "$OUT_DIR/cariddi.html"

# ── cariddi output handling (v1.4.6 writes to output-cariddi/) ──────
EXTRACT_OUT() {
  # cariddi naming: -oh <base> → output-cariddi/<base>.html
  #                   -ot <base> → output-cariddi/<base>.results.txt
  local html_src="$OUT_DIR/output-cariddi/$1.html"
  local txt_src="$OUT_DIR/output-cariddi/$1.results.txt"
  [ -f "$html_src" ] && mv "$html_src" "$OUT_DIR/cariddi.html"
  [ -f "$txt_src" ] && mv "$txt_src" "$OUT_DIR/$2"
}

# ── Pass 1: Full intensive scan ─────────────────────────────────────
log_info "Pass 1: Full intensive scan ..."
(
  cd "$OUT_DIR" || exit 1
  cat "$ALIVE_FILE" | cariddi -intensive -s -info -e -err -ext 1 -c 30 -d 1 -plain \
    -oh "pass1" -ot "pass1" 2>/dev/null
)
EXTRACT_OUT "pass1" "cariddi.txt"

CARIDDI_FOUND=$(wc -l < "$OUT_DIR/cariddi.txt" 2>/dev/null | tr -d ' ')
log_ok "cariddi.txt: $CARIDDI_FOUND findings"

# ── Pass 2: High-value paths ────────────────────────────────────────
log_info "Pass 2: High-value path probing ..."

cat > "$OUT_DIR/high-value-paths.txt" << 'EOF'
/.env
/.env.production
/.git/config
/.svn/entries
/config.json
/wp-config.php
/backup.sql
/database.sql
/error.log
/laravel.log
/php_errors.log
/app/config/database.json
EOF

(
  cd "$OUT_DIR" || exit 1
  cat "$ALIVE_FILE" | cariddi -intensive -e -ef "high-value-paths.txt" -c 30 -d 1 -plain \
    -ot "pass2" 2>/dev/null
)

PASS2_FILE="$OUT_DIR/output-cariddi/pass2.results.txt"
if [ -f "$PASS2_FILE" ] && [ -s "$PASS2_FILE" ]; then
  cat "$PASS2_FILE" | anew "$OUT_DIR/cariddi.txt" > /dev/null
fi

CARIDDI_TOTAL=$(wc -l < "$OUT_DIR/cariddi.txt" 2>/dev/null | tr -d ' ')
log_ok "cariddi.txt: $CARIDDI_TOTAL total findings (both passes)"
rm -rf "$OUT_DIR/output-cariddi"
log_ok "Done. Results in $OUT_DIR/"
