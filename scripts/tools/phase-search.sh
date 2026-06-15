#!/usr/bin/env bash
# =============================================================================
# Phase 9: SEARCH (conditional) — Research payloads, CVEs, bypasses
#
# Usage: ./tools/phase-search.sh <domain> [output_dir]
#
# Prepares research context for @search agent when exploit stalls.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

SEARCH_DIR="$OUT_DIR/search"
mkdir -p "$SEARCH_DIR"

log_info "Preparing research context..."

{
  echo "=== Search Research Context ==="
  echo "Target: $TARGET"
  echo ""
  echo "Exploitation blockers (if any):"
  grep -ri "blocked\|waf\|bypass\|rate.limit\|403\|429" "$OUT_DIR/exploit" 2>/dev/null | head -30 || echo "  (none captured)"
  echo ""
  echo "Research needs:"
  echo "  - Stale/missing payload techniques"
  echo "  - Recent CVEs for identified tech stack"
  echo "  - WAF bypass techniques not yet attempted"
  echo "  - New OOB/interaction methods"
} > "$SEARCH_DIR/research_context.txt"

log_ok "Research context saved to $SEARCH_DIR/research_context.txt"
log_info "Run: @search — research payloads, CVEs, and bypass techniques"
log_info "Phase 9 (search) prepared (conditional — activate if exploit stalls)"
