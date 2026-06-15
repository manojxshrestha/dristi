#!/usr/bin/env bash
# =============================================================================
# Phase 10: CAPTURE — Evidence collection, screenshots, redaction
#
# Usage: ./tools/phase-capture.sh <domain> [output_dir]
#
# Prepares evidence structure for @capture agent.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

EVIDENCE_DIR="$OUT_DIR/evidence"
mkdir -p "$EVIDENCE_DIR" "$OUT_DIR/screenshots"

log_info "Preparing evidence capture structure..."

# Create evidence placeholder per finding
FINDINGS=$(find "$OUT_DIR/nuclei" "$OUT_DIR/secrets" "$OUT_DIR/sqli" "$OUT_DIR/xss" "$OUT_DIR/params" \
  -name '*.txt' 2>/dev/null | head -20 || echo "")

if [ -n "$FINDINGS" ]; then
  for f in $FINDINGS; do
    base=$(basename "$f" .txt)
    finding_dir="$EVIDENCE_DIR/$base"
    mkdir -p "$finding_dir"
    cp "$f" "$finding_dir/raw.txt" 2>/dev/null || true
  done
  log_ok "Evidence structure created for findings"
else
  log_warn "No findings to capture evidence for"
fi

log_info "Capture protocol:"
log_info "  1. For each finding: capture raw HTTP request/response"
log_info "  2. Take Playwright screenshot if DOM/visual"
log_info "  3. Check collaborator if OOB"
log_info "  4. Redact cookies, PII, tokens"
log_info "  5. Save to: $EVIDENCE_DIR/<finding-id>/"
log_info "Run: @capture with @evidence-hygiene agent"
log_info "Phase 10 (capture) prepared"
