#!/usr/bin/env bash
# =============================================================================
# coverage_matrix.sh — Manage Phase 6 agent dispatch tracking
#
# Subcommands:
#   generate <domain>     — Create coverage_matrix.csv from dispatch_list.json
#   status   <domain>     — Show coverage summary (counts per state)
#   resume   <domain>     — List pending+failed agents for re-dispatch
#   update   <domain> <agent-id> <state> [--findings N] [--targets N]
#                         — Update a single agent's status
#   gate     <domain>     — Check if >=90% threshold met (exit 0=pass, 1=fail)
#
# States: pending | complete | failed | skipped
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
source "$TOOLS_DIR/_env.sh"

CMD="${1:?Usage: $0 <generate|status|resume|update|gate> <domain> [args...]}"
shift
TARGET="${1:?Usage: $0 <cmd> <domain> [args...]}"
shift

OUT_DIR="${RECON_BASE}/${TARGET}"
HUNT_DIR="$OUT_DIR/hunt"
DISPATCH_FILE="$HUNT_DIR/dispatch_list.json"
COVERAGE_FILE="$HUNT_DIR/coverage_matrix.csv"

generate() {
  if [ ! -f "$DISPATCH_FILE" ]; then
    log_err "dispatch_list.json not found at $DISPATCH_FILE"
    log_err "Run: bash scripts/dispatch_hunt.sh $TARGET"
    exit 1
  fi

  python3 -c "
import json
with open('$DISPATCH_FILE') as f:
    d = json.load(f)
lines = ['agent,category,priority,dispatched,findings,targets_tested,status']
for a in d['agents']:
    lines.append(f\"{a['id']},{a['category']},{a['priority']},,,,pending\")
with open('$COVERAGE_FILE', 'w') as f:
    f.write('\n'.join(lines) + '\n')
"
  log_ok "Coverage matrix generated: $COVERAGE_FILE ($(grep -c . "$COVERAGE_FILE" 2>/dev/null || echo 0) agents)"
}

status() {
  if [ ! -f "$COVERAGE_FILE" ]; then
    log_err "No coverage matrix at $COVERAGE_FILE"
    exit 1
  fi

  TOTAL=0; PENDING=0; COMPLETE=0; FAILED=0; SKIPPED=0
  while IFS=',' read -r agent category priority dispatched findings targets state; do
    s=$(echo "$state" | tr -d ' \r\n"')
    TOTAL=$((TOTAL + 1))
    case "$s" in
      complete)   COMPLETE=$((COMPLETE + 1)) ;;
      failed)     FAILED=$((FAILED + 1)) ;;
      skipped)    SKIPPED=$((SKIPPED + 1)) ;;
      pending|"") PENDING=$((PENDING + 1)) ;;
    esac
  done < <(tail -n +2 "$COVERAGE_FILE")

  PCT=$(( TOTAL > 0 ? (COMPLETE + FAILED + SKIPPED) * 100 / TOTAL : 0 ))
  log_info "Coverage: $COMPLETE complete + $FAILED failed + $SKIPPED skipped = $((COMPLETE + FAILED + SKIPPED))/$TOTAL ($PCT%)"
  log_info "Pending: $PENDING"
  [ "$PCT" -ge 90 ] && log_ok "Gate threshold met (>=90%)" || log_warn "Below gate threshold (90%)"
}

resume() {
  if [ ! -f "$COVERAGE_FILE" ]; then
    log_err "No coverage matrix at $COVERAGE_FILE"
    exit 1
  fi

  echo "Pending+failed agents (re-dispatch these):"
  RESUME_AGENTS=()
  while IFS=',' read -r agent category priority dispatched findings targets state; do
    s=$(echo "$state" | tr -d ' \r\n"')
    if [ "$s" = "pending" ] || [ "$s" = "failed" ]; then
      echo "  $agent ($state)"
      RESUME_AGENTS+=("$agent")
    fi
  done < <(tail -n +2 "$COVERAGE_FILE")

  echo ""
  log_info "Total to resume: ${#RESUME_AGENTS[@]}"
}

update() {
  AGENT_ID="${1:?Usage: $0 update <domain> <agent-id> <state> [--findings N] [--targets N]}"
  NEW_STATE="${2:?Missing state: pending|complete|failed|skipped}"
  shift 2

  FINDINGS=""
  TARGETS=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --findings) FINDINGS="$2"; shift 2 ;;
      --targets)  TARGETS="$2"; shift 2 ;;
      *) log_err "Unknown option: $1"; exit 1 ;;
    esac
  done

  if [ ! -f "$COVERAGE_FILE" ]; then
    log_err "No coverage matrix at $COVERAGE_FILE"
    exit 1
  fi

  VALID_STATES="pending complete failed skipped"
  if ! echo "$VALID_STATES" | grep -qw "$NEW_STATE"; then
    log_err "Invalid state: $NEW_STATE (must be: $VALID_STATES)"
    exit 1
  fi

  FOUND=false
  TMPFILE=$(mktemp)
  while IFS= read -r line; do
    if echo "$line" | grep -q "^$AGENT_ID,"; then
      FOUND=true
      DISPATCHED="yes"
      [ "$NEW_STATE" = "pending" ] && DISPATCHED=""
      echo "$AGENT_ID,$(echo "$line" | cut -d, -f2),$(echo "$line" | cut -d, -f3),$DISPATCHED,${FINDINGS:-$(echo "$line" | cut -d, -f5)},${TARGETS:-$(echo "$line" | cut -d, -f6)},$NEW_STATE"
    else
      echo "$line"
    fi
  done < "$COVERAGE_FILE" > "$TMPFILE"

  if [ "$FOUND" = false ]; then
    log_err "Agent not found in coverage matrix: $AGENT_ID"
    rm -f "$TMPFILE"
    exit 1
  fi

  mv "$TMPFILE" "$COVERAGE_FILE"
  log_ok "$AGENT_ID → $NEW_STATE (findings=$FINDINGS, targets=$TARGETS)"
}

gate() {
  if [ ! -f "$COVERAGE_FILE" ]; then
    log_err "No coverage matrix at $COVERAGE_FILE"
    exit 1
  fi

  TOTAL=0; PENDING=0; COMPLETE=0; FAILED=0; SKIPPED=0
  while IFS=',' read -r agent category priority dispatched findings targets state; do
    s=$(echo "$state" | tr -d ' \r\n"')
    TOTAL=$((TOTAL + 1))
    case "$s" in
      complete)   COMPLETE=$((COMPLETE + 1)) ;;
      failed)     FAILED=$((FAILED + 1)) ;;
      skipped)    SKIPPED=$((SKIPPED + 1)) ;;
      pending|"") PENDING=$((PENDING + 1)) ;;
    esac
  done < <(tail -n +2 "$COVERAGE_FILE")

  DONE=$((COMPLETE + FAILED + SKIPPED))
  PCT=$(( TOTAL > 0 ? DONE * 100 / TOTAL : 0 ))

  log_info "Phase 6 gate: $DONE/$TOTAL ($PCT%) — ${PENDING} pending"

  if [ "$PCT" -lt 90 ]; then
    log_err "GATE FAILED: $PCT% below 90% threshold. $PENDING agents still pending."
    exit 1
  fi

  log_ok "Gate passed ($PCT%)"
  exit 0
}

case "$CMD" in
  generate) generate ;;
  status)   status ;;
  resume)   resume ;;
  update)   update "$@" ;;
  gate)     gate ;;
  *)
    log_err "Unknown command: $CMD"
    log_err "Usage: $0 <generate|status|resume|update|gate> <domain> [args...]"
    exit 1
    ;;
esac
