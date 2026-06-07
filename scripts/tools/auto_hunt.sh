#!/bin/bash
# =============================================================================
# Auto Hunt Pipeline — full recon + hunt automation
#
# Runs the entire pipeline: recon (Phase 0-3) → hunt (Phase 4-7)
#
# Usage:
#   ./tools/auto_hunt.sh <domain>
#   ./tools/auto_hunt.sh <domain> --skip xss,sqli,nuclei
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--skip xss,sqli,nuclei,secrets]}"
SKIP=""
if [ "${2:-}" = "--skip" ] && [ -n "${3:-}" ]; then
  IFS=',' read -ra SKIP_LIST <<< "$3"
  for s in "${SKIP_LIST[@]}"; do SKIP="$SKIP,$s"; done
fi

skip() { [[ "$SKIP" == *",$1"* ]]; }

START_TS=$(date +%s)
log_info "=== Auto Hunt for: $TARGET ==="
echo ""

# ── Phase 0-3: Recon ───────────────────────────────────────────────
log_info "=== Phase 0-3: Recon ==="
bash "$SCRIPT_DIR/auto_recon.sh" "$TARGET"
echo ""

# ── Phase 4: XSS ───────────────────────────────────────────────────
if ! skip "xss"; then
  log_info "=== Phase 4: XSS Hunting ==="
  bash "$SCRIPT_DIR/auto_xss.sh" "$TARGET"
  echo ""
fi

# ── Phase 5: SQLi ──────────────────────────────────────────────────
if ! skip "sqli"; then
  log_info "=== Phase 5: SQLi Hunting ==="
  bash "$SCRIPT_DIR/auto_sqli.sh" "$TARGET"
  echo ""
fi

# ── Phase 6: Nuclei ────────────────────────────────────────────────
if ! skip "nuclei"; then
  log_info "=== Phase 6: Nuclei Scanning ==="
  bash "$SCRIPT_DIR/auto_nuclei.sh" "$TARGET"
  echo ""
fi

# ── Phase 7: Secrets Validation ────────────────────────────────────
if ! skip "secrets"; then
  log_info "=== Phase 7: Secrets Validation ==="
  bash "$SCRIPT_DIR/auto_secrets.sh" "$TARGET"
  echo ""
fi

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

log_ok "=== Auto Hunt Complete ==="
log_ok "Results in: $BASE_DIR/recon/$TARGET/"
log_ok "Elapsed: ${MINS}m ${SECS}s"
