#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=crlf; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/crlf.txt}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "crlf"

detect() {
  local headers_file="$1"
  # Check for injected headers in response
  grep -qi "^Test:" "$headers_file" 2>/dev/null && return 0
  grep -qi "^X-XSS-Protection:" "$headers_file" 2>/dev/null && return 0
  grep -qiE "^Set-Cookie:.*evil" "$headers_file" 2>/dev/null && return 0
  # Check for response splitting (content-length: 0)
  grep -qi "^Content-Length: 0" "$headers_file" 2>/dev/null && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
while IFS= read -r url || [ -n "$url" ]; do
  [ -z "$url" ] && continue
  info "Testing $url"
  param=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)' | head -1)
  local_hits=0
  while IFS= read -r payload || [ -n "$payload" ]; do
    [ -z "$payload" ] && continue
    test_url=$(inject_payload "$url" "$payload")
    hdrf=$(mktemp)
    curl -s -o /dev/null -D "$hdrf" --max-time 10 "$test_url" 2>/dev/null || true
    if detect "$hdrf"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param: ${payload:0:50}"
      rm -f "$hdrf"; break
    fi
    rm -f "$hdrf"
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "CRLF done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
