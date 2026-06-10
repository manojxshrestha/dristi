#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=cors; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/cors.txt}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "cors"

detect() {
  local headers_file="$1" origin="$2"
  local acao; acao=$(grep -i "^access-control-allow-origin:" "$headers_file" 2>/dev/null | sed 's/.*: //;s/\r//')
  local acc; acc=$(grep -i "^access-control-allow-credentials:" "$headers_file" 2>/dev/null | sed 's/.*: //;s/\r//')
  [ -z "$acao" ] && return 1
  # Origin reflected back
  echo "$acao" | grep -qiF "$origin" && return 0
  # Wildcard with credentials
  echo "$acao" | grep -qi "\*" && [ "$(echo "$acc" | tr '[:upper:]' '[:lower:]')" = "true" ] && return 0
  # Null origin allowed
  echo "$acao" | grep -qi "null" && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
while IFS= read -r url || [ -n "$url" ]; do
  [ -z "$url" ] && continue
  info "Testing $url"
  param=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)' | head -1)
  local_hits=0
  while IFS= read -r origin || [ -n "$origin" ]; do
    [ -z "$origin" ] && continue
    hdrf=$(mktemp)
    curl -s -o /dev/null -D "$hdrf" --max-time 10 \
      -H "Origin: $origin" -H "Host: $(echo "$url" | sed 's|https\?://||;s|/.*||')" \
      "$url" 2>/dev/null || true
    if detect "$hdrf" "$origin"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "Origin: $origin" >> "$HITS_DIR/${safe}_${param}.txt"
      grep -i "^access-control" "$hdrf" >> "$HITS_DIR/${safe}_${param}.txt" 2>/dev/null || true
      log "HIT on $param: Origin=$origin"
      rm -f "$hdrf"; break
    fi
    rm -f "$hdrf"
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "CORS done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
