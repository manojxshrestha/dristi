#!/usr/bin/env bash
# =============================================================================
# pipeline.sh — Dristi 12-Phase Security Testing Pipeline (Script-Driven)
#
# Runs each phase in strict order. The AI never decides "what's next" —
# this script does. The AI is called ONLY for analysis within each phase.
#
# Usage:
#   bash scripts/pipeline.sh <domain> [phase-start] [phase-end]
#
# Examples:
#   bash scripts/pipeline.sh target.com           # Run all 12 phases
#   bash scripts/pipeline.sh target.com 1-4       # Run phases 1 through 4
#   bash scripts/pipeline.sh target.com 3         # Run phase 3 only
#   bash scripts/pipeline.sh target.com 6 10      # Run phases 6 through 10
# =============================================================================

set -euo pipefail

# ── Resolve paths ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
source "$TOOLS_DIR/_env.sh"

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${CYAN}  Phase $1: $2${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

# ── Argument parsing ────────────────────────────────────────────────────────
TARGET="${1:?Usage: $0 <domain> [phase-start] [phase-end]}"
PHASE_START="${2:-1}"
PHASE_END="${3:-12}"

if [ $# -eq 2 ]; then
  if [[ "$2" == *-* ]]; then
    PHASE_START="${2%-*}"
    PHASE_END="${2#*-}"
  else
    PHASE_START="$2"
    PHASE_END="$2"
  fi
fi

OUT_DIR="${RECON_BASE}/${TARGET}"
mkdir -p "$OUT_DIR"

# ── Phase definitions ───────────────────────────────────────────────────────
PHASES=(
  "1:scope:Scope registration — register target, scaffold engagement"
  "2:auth:Auth & WAF detection — get credentials, identify WAF"
  "3:intel:Passive intel — WHOIS, cloud, spoof, third-party misconfigs"
  "4:recon:Reconnaissance — subdomains, crawl, params, secrets, cloud"
  "5:surface:Surface analysis — classify endpoints, prioritize attack surface"
  "6:hunt:Vulnerability hunting — test all bug classes"
  "7:deepthink:Deep analysis — (conditional) gap analysis when hunt yields zero"
  "8:exploit:Exploitation — deepen findings, chain, escalate impact"
  "9:search:Research — (conditional) payload/CVE research when exploit stalls"
  "10:capture:Evidence capture — screenshots, redaction, evidence hygiene"
  "11:validate:Validation — re-validate PoCs, 7-Question Gate"
  "12:report:Report — coverage check, generate final report"
)

# ── Phase runner ────────────────────────────────────────────────────────────
run_phase() {
  local num="$1"
  local name="$2"
  local script="$TOOLS_DIR/phase-${name}.sh"

  step "$num" "$name — $3"

  if [ ! -f "$script" ]; then
    err "Script not found: $script"
    warn "Run the phase manually: docs/pipeline.md#$name"
    return 1
  fi

  if [ ! -x "$script" ]; then
    chmod +x "$script"
  fi

  if bash "$script" "$TARGET" "$OUT_DIR"; then
    ok "Phase $num ($name) completed"
  else
    warn "Phase $num ($name) exited with code $?"
  fi

  # Phase gate
  if [ -f "$TOOLS_DIR/phase_gate.sh" ]; then
    bash "$TOOLS_DIR/phase_gate.sh" "$num" "$TARGET" || true
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           Dristi Pipeline — $TARGET${NC}"
echo -e "${CYAN}║           Phases $PHASE_START → $PHASE_END${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Validate environment
if [ -f "$TOOLS_DIR/validate-env.sh" ]; then
  bash "$TOOLS_DIR/validate-env.sh" || true
fi

# Run requested phases
for entry in "${PHASES[@]}"; do
  num="${entry%%:*}"
  rest="${entry#*:}"
  name="${rest%%:*}"
  desc="${rest#*:}"

  if [ "$num" -ge "$PHASE_START" ] && [ "$num" -le "$PHASE_END" ]; then
    run_phase "$num" "$name" "$desc"
  fi
done

info "Pipeline complete (phases $PHASE_START-$PHASE_END)"
ok "Output in: $OUT_DIR"
echo ""
echo "  Next: Review results and call the appropriate AI agent for analysis."
echo "  Agents: @pintel (intel), @recon (recon), @surface (surface), @hunt (hunt)"
