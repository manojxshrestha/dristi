#!/usr/bin/env bash
# =============================================================================
# Phase Gate — Enforce pipeline ordering + Phase 6 coverage threshold
#
# Called by pipeline.sh after each phase.
# For Phase 6 specifically, checks that hunt agents were dispatched.
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

# ── Phase 6: Coverage gate ──────────────────────────────────────────────
# NOTE: This gate is called TWICE:
#   1. From pipeline.sh after bash tool execution (dispatch files don't exist yet → soft pass)
#   2. By the autopilot/consult agent AFTER ALL agents dispatched (enforced)
if [ "$PHASE_NUM" = "6" ]; then
  COVERAGE_FILE="$OUT_DIR/hunt/coverage_matrix.csv"
  DISPATCH_FILE="$OUT_DIR/hunt/dispatch_list.json"

  if [ ! -f "$DISPATCH_FILE" ]; then
    # Called from pipeline.sh before AI dispatch — soft pass
    log_info "Phase 6: No dispatch list yet (AI agents not dispatched)"
    log_info "Full gate enforcement runs after agent dispatch completes"
  elif [ ! -f "$COVERAGE_FILE" ]; then
    log_info "Phase 6: No coverage matrix yet (agents dispatched but not tracked)"
  else
    # Full gate enforcement — dispatch files exist
    TOTAL=$(python3 -c "
import json
with open('$DISPATCH_FILE') as f:
    d = json.load(f)
print(d['summary']['total'])
" 2>/dev/null || echo "0")

    # Count completed agents
    COMPLETED=0
    PENDING=0
    while IFS=',' read -r agent category priority dispatched findings status; do
      s=$(echo "$status" | tr -d ' \r\n"')
      case "$s" in
        complete|done|finished|dispatched) COMPLETED=$((COMPLETED + 1)) ;;
        pending|skipped|"") PENDING=$((PENDING + 1)) ;;
        *) COMPLETED=$((COMPLETED + 1)) ;;
      esac
    done < <(tail -n +2 "$COVERAGE_FILE")

    PCT=$(( TOTAL > 0 ? COMPLETED * 100 / TOTAL : 0 ))
    log_info "Phase 6 dispatch coverage: $COMPLETED/$TOTAL agents ($PCT%)"

    if [ "$PCT" -lt 90 ]; then
      log_err "PHASE 6 GATE FAILED: Only $PCT% of agents dispatched ($COMPLETED/$TOTAL)"
      log_err "This means vulnerability categories were skipped."
      log_err "Run dispatch_hunt.sh again and dispatch ALL agents before proceeding."
      log_err "Gate file NOT written — pipeline will not advance past Phase 6."
      exit 1
    fi

    if [ "$PENDING" -gt 0 ]; then
      log_warn "Phase 6: $PENDING agents still pending — but $PCT% threshold met"
      log_warn "For best coverage, dispatch remaining agents"
    fi
  fi
fi

# ── Mark this phase as completed ────────────────────────────────────────
date -Iseconds > "$GATE_DIR/phase${PHASE_NUM}_done"

# ── Verify previous phase gates exist ───────────────────────────────────
if [ "$PHASE_NUM" -gt 1 ]; then
  PREV=$((PHASE_NUM - 1))
  if [ ! -f "$GATE_DIR/phase${PREV}_done" ]; then
    log_warn "Phase $PREV gate not found! Did you skip a phase?"
    log_warn "Pipeline ordering violation — run phase $PREV first"
  fi
fi

log_ok "Gate passed for Phase $PHASE_NUM"
