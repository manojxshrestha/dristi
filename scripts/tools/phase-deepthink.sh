#!/usr/bin/env bash
# =============================================================================
# Phase 7: DEEPTHINK (conditional) — Gap analysis when hunt yields zero
#
# Usage: ./tools/phase-deepthink.sh <domain> [output_dir]
#
# This phase creates a gap analysis brief. Call @deepthink agent to analyze.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

DEEP_DIR="$OUT_DIR/deepthink"
mkdir -p "$DEEP_DIR"

log_info "Preparing deepthink gap analysis context..."

# Collect what we have
{
  echo "=== DeepThink Gap Analysis ==="
  echo "Target: $TARGET"
  echo ""
  echo "Findings summary:"
  echo "  Secrets: $(find "$OUT_DIR/secrets" -name '*.txt' 2>/dev/null | xargs cat 2>/dev/null | wc -l) findings"
  echo "  SQLi:    $(find "$OUT_DIR/sqli" -name '*.txt' 2>/dev/null | xargs cat 2>/dev/null | wc -l) findings"
  echo "  XSS:     $(find "$OUT_DIR/xss" -name '*.txt' 2>/dev/null | xargs cat 2>/dev/null | wc -l) findings"
  echo ""
  echo "Attack surface:"
  echo "  Tiers: $(cat "$OUT_DIR/surface/endpoint_map_ranked.txt" 2>/dev/null | head -5 || echo 'N/A')"
  echo ""
  echo "Questions to investigate:"
  echo "  1. Are there hidden endpoints not discovered by crawling?"
  echo "  2. Could WAF be blocking payloads? What bypasses remain untested?"
  echo "  3. Are there business logic flaws that automated scanners miss?"
  echo "  4. Is the attack surface fully enumerated?"
  echo "  5. What manual techniques would a human researcher try next?"
} > "$DEEP_DIR/gap_analysis.txt"

log_ok "Gap analysis context saved to $DEEP_DIR/gap_analysis.txt"
log_info "Run: @deepthink — loads gap context and performs first-principles analysis"
log_info "Phase 7 (deepthink) prepared (conditional — activate if needed)"
