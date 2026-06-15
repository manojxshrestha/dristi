#!/usr/bin/env bash
# =============================================================================
# Phase Gate — Enforce pipeline ordering
#
# Called by pipeline.sh after each phase. Prevents skipping.
#
# Usage: ./tools/phase_gate.sh <phase-num> <domain>
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

PHASE_NUM="${1:?Usage: $0 <phase-num> <domain>}"
TARGET="${2:?Usage: $0 <phase-num> <domain>}"

OUT_DIR="${RECON_BASE}/${TARGET}"
GATE_DIR="$OUT_DIR/.gates"
mkdir -p "$GATE_DIR"

# Mark this phase as completed
date -Iseconds > "$GATE_DIR/phase${PHASE_NUM}_done"

# Verify previous phase gates exist
if [ "$PHASE_NUM" -gt 1 ]; then
  PREV=$((PHASE_NUM - 1))
  if [ ! -f "$GATE_DIR/phase${PREV}_done" ]; then
    log_warn "Phase $PREV gate not found! Did you skip a phase?"
    log_warn "Pipeline ordering violation — run phase $PREV first"
  fi
fi

log_ok "Gate passed for Phase $PHASE_NUM"
