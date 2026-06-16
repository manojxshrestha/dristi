#!/usr/bin/env bash
# =============================================================================
# Phase 12: REPORT — Coverage check, generate final report
#
# Usage: ./tools/phase-report.sh <domain> [output_dir]
#
# Prepares report context for @report-writing agent.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

REPORT_DIR="$OUT_DIR/report"
mkdir -p "$REPORT_DIR"

log_info "Compiling report context..."

# Summarize everything
{
  echo "=== Engagement Summary ==="
  echo "Target: $TARGET"
  echo "Started: $(cat "$OUT_DIR/scope/started.txt" 2>/dev/null || echo 'N/A')"
  echo ""

  echo "--- Scope ---"
  cat "$OUT_DIR/scope/target.txt" 2>/dev/null || echo "N/A"
  echo ""

  echo "--- Findings Counts ---"
  for dir in secrets sqli xss params directories; do
    count=$(find "$OUT_DIR/$dir" -name '*.txt' 2>/dev/null | xargs cat 2>/dev/null | grep -ci "finding\|vuln\|issue\|CVE-\|risk" 2>/dev/null || echo 0)
    echo "  $dir: $count"
  done
  echo ""

  echo "--- Validated Findings ---"
  cat "$OUT_DIR/validate/findings_for_validation.txt" 2>/dev/null | head -30 || echo "N/A"
  echo ""

  echo "=== End ==="
} > "$REPORT_DIR/report_context.txt"

log_ok "Report context saved to $REPORT_DIR/report_context.txt"
log_info "Run: @report-writing (HackerOne format) or @bugcrowd-reporting (Bugcrowd)"
log_info "Phase 12 (report) prepared"
