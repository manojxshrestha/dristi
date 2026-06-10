#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=clickjacking; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/clickjacking.txt}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$URLS_FILE" ] && [ ! -t 0 ] && URLS_FILE=/dev/stdin
pat_ref "$CLASS"

detect() {
  local headers_file="$1"
  local xfo; xfo=$(grep -i "^x-frame-options:" "$headers_file" 2>/dev/null | sed 's/.*: //;s/\r//')
  local csp; csp=$(grep -i "^content-security-policy:" "$headers_file" 2>/dev/null | sed 's/.*: //;s/\r//')
  # Check for frame-ancestors in CSP
  local has_fa=1
  echo "$csp" | grep -qi "frame-ancestors" && has_fa=0
  # Missing XFO + no CSP frame-ancestors = vulnerable
  [ -z "$xfo" ] && [ "$has_fa" -eq 1 ] && return 0
  # XFO set to ALLOW (not DENY or SAMEORIGIN)
  echo "$xfo" | grep -qi "allow" && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
if [ -f "$URLS_FILE" ]; then
  while IFS= read -r url || [ -n "$url" ]; do
    [ -z "$url" ] && continue
    info "Testing $url"
    hdrf=$(mktemp)
    curl -s -o /dev/null -D "$hdrf" --max-time 10 -L "$url" 2>/dev/null || true
    if detect "$hdrf"; then
      safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      cat "$hdrf" > "$HITS_DIR/${safe}_headers.txt"
      log "MISSING X-Frame-Options and CSP frame-ancestors on $url"
      HIT_COUNT=$((HIT_COUNT + 1))
    fi
    rm -f "$hdrf"; TOTAL=$((TOTAL + 1))
  done < "$URLS_FILE"
fi
log "Clickjacking done: $HIT_COUNT/$TOTAL URLs missing framing protection"
