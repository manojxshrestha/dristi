#!/bin/bash
# =============================================================================
# Automated SQLi Hunting — sqlmap on gf_sqli.txt
#
# Usage:
#   ./tools/auto_sqli.sh <domain>
#   ./tools/auto_sqli.sh <domain> --gf-sqli <gf_sqli.txt>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--gf-sqli <file>]}"
GF_SQLI="${3:-$BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/params/gf_sqli.txt}"
OUT_DIR="$BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/sqli"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Ensure sqlmap is installed ──────────────────────────────────────
if ! command -v sqlmap &>/dev/null; then
  log_info "Installing sqlmap ..."
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /tmp/sqlmap 2>/dev/null
  chmod +x /tmp/sqlmap/sqlmap.py
  sudo ln -sf /tmp/sqlmap/sqlmap.py /usr/local/bin/sqlmap
  log_ok "sqlmap installed"
fi

SQLMAP="sqlmap"

# ── Check input ─────────────────────────────────────────────────────
if [ ! -f "$GF_SQLI" ] || [ ! -s "$GF_SQLI" ]; then
  log_warn "gf_sqli.txt not found or empty: $GF_SQLI"
  log_info "Run param_extract.sh first"
  exit 0
fi

NURLS=$(wc -l < "$GF_SQLI" | tr -d ' ')

# ── Batch sqlmap scan ───────────────────────────────────────────────
log_info "Running sqlmap on $NURLS SQLi candidates (batch, level 2) ..."

# Use batch mode to skip prompts, level 2 for moderate depth
$SQLMAP -m "$GF_SQLI" \
  --batch \
  --level 2 \
  --random-agent \
  --threads 5 \
  --time-sec 5 \
  --output-dir="$OUT_DIR/sqlmap_output" \
  --flush-session \
  2>/dev/null

# ── Parse results ──────────────────────────────────────────────────
if [ -d "$OUT_DIR/sqlmap_output" ]; then
  find "$OUT_DIR/sqlmap_output" -name "log" -exec grep -l "Parameter:" {} \; > "$OUT_DIR/sqli_found.txt" 2>/dev/null
  SQLI_FOUND=$(wc -l < "$OUT_DIR/sqli_found.txt" 2>/dev/null | tr -d ' ')
  log_ok "sqlmap: $SQLI_FOUND injectable parameters"
  [ "$SQLI_FOUND" -gt 0 ] && log_info "Check $OUT_DIR/sqlmap_output/ for details"
else
  log_ok "sqlmap: 0 injectable parameters"
fi

log_ok "Done. Results in $OUT_DIR/"
