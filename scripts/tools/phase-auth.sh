#!/usr/bin/env bash
# =============================================================================
# Phase 2: AUTH — Get credentials, detect WAF
#
# Usage: ./tools/phase-auth.sh <domain> [output_dir]
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

AUTH_DIR="$OUT_DIR/auth"
mkdir -p "$AUTH_DIR"

# WAF detection
log_info "Detecting WAF..."
if command -v curl &>/dev/null; then
  {
    echo "=== WAF Detection ==="
    curl -sI "https://$TARGET" 2>&1 | grep -iE "server:|cf-ray|x-sucuri|x-iinfo|x-mod-security|x-waf|cloudflare|akamai|fastly"
    echo ""
    echo "=== Response Headers ==="
    curl -sI "https://$TARGET" 2>&1
  } > "$AUTH_DIR/waf_detection.txt"
  log_ok "WAF headers saved to $AUTH_DIR/waf_detection.txt"
fi

log_ok "Phase 2 (auth) complete — credentials ready, WAF fingerprinted"
log_info "Next: Provide credentials/session tokens if required, then run Phase 3 (intel)"
