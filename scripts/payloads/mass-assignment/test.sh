#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=mass-assignment; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/mass-assignment.txt}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && [ ! -t 0 ] && URLS_FILE=/dev/stdin
pat_ref "$CLASS"

detect() {
  local body="$1" status="$2"
  # 200/201 with different response = field accepted
  [ "$status" = "200" ] || [ "$status" = "201" ] || [ "$status" = "204" ] && return 0
  # 500 = possible processing attempt
  [ "$status" = "500" ] && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
if [ -f "$URLS_FILE" ]; then
  while IFS= read -r url || [ -n "$url" ]; do
    [ -z "$url" ] && continue; info "Testing $url"
    param=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)' | head -1)
    while IFS= read -r payload || [ -n "$payload" ]; do
      [ -z "$payload" ] && continue
      tmpf=$(mktemp); hdrf=$(mktemp)
      # Send as JSON body to POST endpoints
      method="POST"
      echo "$url" | grep -qiE "(get|delete|/api/)" && method="GET"
      if [ "$method" = "POST" ]; then
        curl -s -o "$tmpf" -D "$hdrf" --max-time 10 \
          -X POST -H "Content-Type: application/json" -d "$payload" \
          "$url" 2>/dev/null || true
      else
        # Try as query param injection
        inj_url="$url&$(echo "$payload" | tr -d '{}"' | tr ',' '&' | tr ':' '=')"
        curl -s -o "$tmpf" -D "$hdrf" --max-time 10 "$inj_url" 2>/dev/null || true
      fi
      status=$(grep -i "^http/" "$hdrf" 2>/dev/null | awk '{print $2}' || echo "000")
      body=$(cat "$tmpf" 2>/dev/null || true)
      if detect "$body" "$status"; then
        safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
        echo "[$status] $payload" >> "$HITS_DIR/${safe}_${param}.txt"
        log "MA on $url (status $status): ${payload:0:50}"
        HIT_COUNT=$((HIT_COUNT + 1))
        rm -f "$tmpf" "$hdrf"; break
      fi
      rm -f "$tmpf" "$hdrf"
      TOTAL=$((TOTAL + 1))
    done < "$PAYLOADS"
  done < "$URLS_FILE"
fi
log "Mass Assignment done: $HIT_COUNT URLs with hits (manual verification required)"
