#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=http-param-pollution; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/http-param-pollution.txt}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$URLS_FILE" ] && [ ! -t 0 ] && URLS_FILE=/dev/stdin
pat_ref "$CLASS"

detect() {
  local baseline_body="$1" test_body="$2"
  # Different response = parameter pollution worked
  [ "$baseline_body" != "$test_body" ] && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
if [ -f "$URLS_FILE" ]; then
  while IFS= read -r url || [ -n "$url" ]; do
    [ -z "$url" ] && continue; info "Testing $url"
    param=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)' | head -1)
    [ -z "$param" ] && continue
    
    # Baseline: normal request
    bf=$(mktemp); curl -s -o "$bf" --max-time 10 "$url" 2>/dev/null || true
    baseline=$(cat "$bf" 2>/dev/null || true)
    
    # HPP: duplicate the param
    value=$(echo "$url" | grep -oP "(?<=$param=)[^&]+")
    hpp_url=$(echo "$url" | sed "s/$param=[^&]*/$param=$value&$param=$value/")
    tf=$(mktemp); curl -s -o "$tf" --max-time 10 "$hpp_url" 2>/dev/null || true
    hpp_body=$(cat "$tf" 2>/dev/null || true)
    
    if detect "$baseline" "$hpp_body"; then
      safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$hpp_url" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HPP difference on $param"
      HIT_COUNT=$((HIT_COUNT + 1))
    fi
    rm -f "$bf" "$tf"; TOTAL=$((TOTAL + 1))
  done < "$URLS_FILE"
fi
log "HTTP Parameter Pollution done: $HIT_COUNT/$TOTAL with response differences"
