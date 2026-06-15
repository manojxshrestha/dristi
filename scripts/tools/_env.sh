#!/usr/bin/env bash
# =============================================================================
# Shared Environment Resolution — source this in every tool script
# =============================================================================

# Auto-detect repo root and cd there
DRISTI_ROOT="${DRISTI_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$DRISTI_ROOT" 2>/dev/null || true

# Engagement ID (optional — no longer used in path construction)
ENGAGEMENT_ID="${ENGAGEMENT_ID:-}"

# Common output base — no default-engagement layer
RECON_BASE="$DRISTI_ROOT/engagements/recon"

# Tool paths
export PATH="$HOME/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

# Colors
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

# Common tool check
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_warn "$1 not found — skipping"
        return 1
    fi
    return 0
}