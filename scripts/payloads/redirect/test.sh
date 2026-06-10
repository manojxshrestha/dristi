#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=redirect; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/urls/redirect.txt}"
HITS_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "redirect"

detect() {
  local url="$1" test_url="$2" redirect_url="$3"
  [ -z "$redirect_url" ] && return 1
  local base_domain; base_domain=$(echo "$url" | sed 's|https\?://||;s|/.*||;s|:.*||')
  local redir_domain; redir_domain=$(echo "$redirect_url" | sed 's|https\?://||;s|/.*||;s|:.*||')
  # Redirect to different domain = potential open redirect
  [ -n "$redir_domain" ] && [ "$redir_domain" != "$base_domain" ] && return 0
  # Redirect with path traversal
  echo "$redirect_url" | grep -qiE "(//evil|//attacker|\.com\.|@)" 2>/dev/null && return 0
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
    # Follow no redirects, capture Location header
    redirect_url=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 10 "$test_url" 2>/dev/null || true)
    if [ -n "$redirect_url" ] && detect "$url" "$test_url" "$redirect_url"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "$payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param -> $redirect_url"
      break
    fi
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "Redirect done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
