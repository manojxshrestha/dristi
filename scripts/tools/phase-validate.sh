#!/usr/bin/env bash
# =============================================================================
# Phase 11: VALIDATE — Re-validate PoCs, 7-Question Gate
#
# Usage: ./tools/phase-validate.sh <domain> [output_dir]
#
# Prepares findings for @validate agent (triage-validation).
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

VALIDATE_DIR="$OUT_DIR/validate"
mkdir -p "$VALIDATE_DIR"

log_info "Preparing findings for validation..."

# List all findings
FINDINGS_FILE="$VALIDATE_DIR/findings_for_validation.txt"
{
  echo "=== Findings for Validation ==="
  echo "Target: $TARGET"
  echo ""

  for dir in secrets sqli xss params directories; do
    if [ -d "$OUT_DIR/$dir" ]; then
      for f in "$OUT_DIR/$dir"/*.txt; do
        [ -f "$f" ] && {
          echo "--- $(basename "$f" .txt) ---"
          head -5 "$f"
          echo ""
        }
      done
    fi
  done

  echo ""
  echo "=== 7-Question Gate ==="
  echo "Q1: Can an attacker use this RIGHT NOW with a real HTTP request?"
  echo "Q2: Is the impact on the program's accepted-impact list?"
  echo "Q3: Is the vulnerable asset in scope?"
  echo "Q4: Does it work without privileged access an attacker can't get?"
  echo "Q5: Is this not already known or documented behavior?"
  echo "Q6: Can impact be proved beyond 'technically possible'?"
  echo "Q7: Is this NOT on the never-submit list?"
} > "$FINDINGS_FILE"

log_ok "Validation context saved to $FINDINGS_FILE"
log_info "Run: @validate + @triage-validation — runs 7-Question Gate on each finding"
log_info "Phase 11 (validate) prepared"
