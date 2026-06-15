#!/usr/bin/env bash
# =============================================================================
# Environment Validation — run at start of each phase
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

log_info "Validating environment..."

# 1. Must be in repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ "$REPO_ROOT" != "$(pwd)" ]; then
    log_err "Not in repo root. Current: $(pwd), Expected: $REPO_ROOT"
    log_err "Run: cd $DRISTI_ROOT"
    exit 1
fi
log_ok "In repo root: $DRISTI_ROOT"

# 2. Engagement ID (optional — informational only)
if [ -n "$ENGAGEMENT_ID" ]; then
  log_info "Engagement ID: $ENGAGEMENT_ID"
else
  log_info "Engagement ID: not set (single-target mode)"
fi

# 3. Output base exists/writable
mkdir -p "$RECON_BASE"
if [ ! -w "$RECON_BASE" ]; then
    log_err "Cannot write to $RECON_BASE"
    exit 1
fi
log_ok "Output base: $RECON_BASE"

# 4. Required tools in PATH
MISSING=0
for tool in subfinder httpx dnsx nuclei curl jq git python3; do
    if ! command -v "$tool" &>/dev/null; then
        log_warn "Missing tool: $tool"
        MISSING=1
    fi
done
[ $MISSING -eq 0 ] && log_ok "Core tools present" || log_warn "Some tools missing (may be installed on demand)"

# 5. _env.sh sourced correctly
if [ -z "$DRISTI_ROOT" ] || [ -z "$RECON_BASE" ]; then
    log_err "_env.sh not sourced correctly"
    exit 1
fi
log_ok "Environment loaded: DRISTI_ROOT=$DRISTI_ROOT"

log_ok "Environment validation PASSED"
exit 0