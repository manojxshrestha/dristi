#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=nosqli; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/nosqli.txt}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "nosqli"

detect() {
  local body="$1" status="$2" duration="$3" payload="$4"
  # Auth bypass: different response from expected
  [ "$status" = "200" ] && echo "$body" | grep -qiE "(admin|dashboard|welcome|logged)" && return 0
  # Time-based: $where sleep
  [ "$(echo "$duration" | cut -d. -f1)" -ge 5 ] && echo "$payload" | grep -qi "sleep" && return 0
  # Error messages
  echo "$body" | grep -qiE "(Mongo|MongoDB|NoSQL|CastError|Cannot read property)" 2>/dev/null && return 0
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
    tmpf=$(mktemp); resp=$(fetch_url "$test_url" "$tmpf")
    status=$(echo "$resp" | awk '{print $1}')
    duration=$(echo "$resp" | awk '{print $2}')
    body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if detect "$body" "$status" "$duration" "$payload"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "[$status] $payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param (status $status): ${payload:0:60}"
      rm -f "$tmpf"; break
    fi
    rm -f "$tmpf"
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "NoSQLi done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
