#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=prototype-pollution; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/prototype-pollution.txt}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && [ ! -t 0 ] && URLS_FILE=/dev/stdin
pat_ref "$CLASS"

detect() {
  local body="$1" status="$2" payload="$3"
  # Check for prototype pollution indicators
  # __proto__ reflected or accepted
  echo "$body" | grep -qi "__proto__" && return 0
  # Status change indicates processing
  [ "$status" != "404" ] && [ "$status" != "400" ] && [ "$status" != "500" ] && return 0
  return 1
}

TOTAL=0; HIT_COUNT=0
if [ -f "$URLS_FILE" ]; then
  while IFS= read -r url || [ -n "$url" ]; do
    [ -z "$url" ] && continue; info "Testing $url"
    local_hits=0
    while IFS= read -r payload || [ -n "$payload" ]; do
      [ -z "$payload" ] && continue
      content_type="application/json"
      [[ "$payload" == *"__proto__"* ]] && content_type="application/json"
      [[ "$payload" == *"constructor"* ]] && content_type="application/json"
      tmpf=$(mktemp); hdrf=$(mktemp)
      curl -s -o "$tmpf" -D "$hdrf" --max-time 10 \
        -X POST -H "Content-Type: $content_type" -d "$payload" "$url" 2>/dev/null || true
      status=$(grep -i "^http/" "$hdrf" 2>/dev/null | awk '{print $2}' || echo "000")
      body=$(cat "$tmpf" 2>/dev/null || true)
      if detect "$body" "$status" "$payload"; then
        local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
        echo "$payload" >> "$HITS_DIR/${safe}_prototype.txt"
        log "Possible PP on $url (status $status)"
        rm -f "$tmpf" "$hdrf"; break
      fi
      rm -f "$tmpf" "$hdrf"
      TOTAL=$((TOTAL + 1))
    done < "$PAYLOADS"
    [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
  done < "$URLS_FILE"
fi
log "Prototype Pollution done: $HIT_COUNT URLs with hits (manual verification required)"
