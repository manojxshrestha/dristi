#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=xss; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file] [max-payloads]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/xss.txt}"
MAX="${3:-50}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "xss"

detect() {
  local body="$1" payload="$2"
  # Check if payload is reflected in response body
  local safe_payload
  safe_payload=$(echo "$payload" | sed 's/[][\.*^$()+?{|]/\\&/g')
  echo "$body" | grep -qi "$safe_payload" 2>/dev/null && return 0
  # Also check for common XSS indicators even if payload itself is modified
  echo "$body" | grep -qiE "(alert|confirm|prompt)\(.*\)" 2>/dev/null && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
while IFS= read -r url || [ -n "$url" ]; do
  [ -z "$url" ] && continue
  info "Testing $url"
  param=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)' | head -1)
  local_hits=0; count=0
  while IFS= read -r payload || [ -n "$payload" ]; do
    [ -z "$payload" ] && continue; count=$((count + 1))
    [ "$count" -gt "$MAX" ] && break
    test_url=$(inject_payload "$url" "$payload")
    tmpf=$(mktemp); resp=$(fetch_url "$test_url" "$tmpf")
    body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if detect "$body" "$payload"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param: ${payload:0:60}"
      break
    fi
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "XSS done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
