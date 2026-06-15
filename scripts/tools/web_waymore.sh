#!/bin/bash
# =============================================================================
# Waymore — passive URL collection from Wayback Machine + AlienVault etc
#
# Usage:
#   ./tools/web_waymore.sh <domain>
#
# Output: <crawl>/waygauurls.txt
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET="${1:?Usage: $0 <domain>}"

OUT_DIR="${RECON_BASE}/$TARGET/crawl"
mkdir -p "$OUT_DIR"

# ── Setup waymore venv ──────────────────────────────────────────────
WAYMORE_DIR="$BASE_DIR/tools/waymore"
WAYMORE_BIN=""
if [ -f "$WAYMORE_DIR/venv/bin/waymore" ]; then
  WAYMORE_BIN="$WAYMORE_DIR/venv/bin/waymore"
elif command -v waymore &>/dev/null; then
  WAYMORE_BIN="waymore"
else
  log_info "Installing waymore in virtual environment ..."
  mkdir -p "$WAYMORE_DIR"
  python3 -m venv "$WAYMORE_DIR/venv"
  uv pip install --python "$WAYMORE_DIR/venv/bin/python" waymore -q 2>/dev/null
  WAYMORE_BIN="$WAYMORE_DIR/venv/bin/waymore"
  log_ok "waymore installed"
fi

# ── Waymore ─────────────────────────────────────────────────────────
log_info "Running waymore ..."
$WAYMORE_BIN -i "$TARGET" -mode U -oU "$OUT_DIR/wayurls.txt" 2>/dev/null
NWAY=$(wc -l < "$OUT_DIR/wayurls.txt" 2>/dev/null | tr -d ' ')
NWAY=${NWAY:-0}
log_ok "waymore: $NWAY URLs"

# ── Dedup with uro ──────────────────────────────────────────────────
log_info "Deduping waymore URLs with uro ..."
uro < "$OUT_DIR/wayurls.txt" 2>/dev/null | sort -u > "$OUT_DIR/waygauurls.txt"
NWAYGAU=$(wc -l < "$OUT_DIR/waygauurls.txt" 2>/dev/null | tr -d ' ')
NWAYGAU=${NWAYGAU:-0}
log_ok "waygauurls.txt: $NWAYGAU URLs"
