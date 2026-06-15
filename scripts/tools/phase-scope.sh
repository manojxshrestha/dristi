#!/usr/bin/env bash
# =============================================================================
# Phase 1: SCOPE — Register target, scaffold engagement
#
# Usage: ./tools/phase-scope.sh <domain> [output_dir]
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

mkdir -p "$OUT_DIR"/{scope,intel,recon,crawl,subdomains,secrets,directories,vhost,evidence,screenshots}

log_ok "Scaffold created at $OUT_DIR"

# Write target info
echo "$TARGET" > "$OUT_DIR/scope/target.txt"
date -I > "$OUT_DIR/scope/started.txt"
log_ok "Target registered: $TARGET"

# Quick connectivity check
if command -v curl &>/dev/null; then
  if curl -sI "https://$TARGET" --connect-timeout 5 &>/dev/null; then
    log_ok "Target reachable via HTTPS"
  else
    log_warn "Target not reachable via HTTPS (may be offline or non-web)"
  fi
fi

log_ok "Phase 1 (scope) complete — ready for Phase 2"
