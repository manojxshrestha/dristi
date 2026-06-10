#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=idor; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/idor.txt}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "idor"

# IDOR detection: fetch with low ID vs high ID, compare response sizes
# Large difference might indicate different resource access
detect() {
  local baseline_size="$1" current_size="$2" baseline_status="$3" current_status="$4"
  # Different resource accessed (same status, different content)
  if [ "$baseline_status" = "$current_status" ] && [ "$baseline_status" != "404" ]; then
    local diff=$((current_size - baseline_size))
    [ "${diff#-}" -gt 100 ] && return 0  # significant size difference
  fi
  return 1
}

TOTAL=0; HIT_COUNT=0
while IFS= read -r url || [ -n "$url" ]; do
  [ -z "$url" ] && continue
  info "Testing $url"
  param=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)' | head -1)
  local_hits=0
  # Get baseline with first payload (usually "1")
  baseline_payload=$(head -1 "$PAYLOADS")
  bl_url=$(inject_payload "$url" "$baseline_payload")
  bl_tmp=$(mktemp); bl_resp=$(fetch_url "$bl_url" "$bl_tmp")
  bl_size=$(echo "$bl_resp" | awk '{print $3}')
  bl_status=$(echo "$bl_resp" | awk '{print $1}')
  bl_body=$(cat "$bl_tmp" 2>/dev/null || true); rm -f "$bl_tmp"
  TOTAL=$((TOTAL + 1))

  while IFS= read -r payload || [ -n "$payload" ]; do
    [ -z "$payload" ] && continue
    [ "$payload" = "$baseline_payload" ] && continue
    test_url=$(inject_payload "$url" "$payload")
    tmpf=$(mktemp); resp=$(fetch_url "$test_url" "$tmpf")
    status=$(echo "$resp" | awk '{print $1}')
    size=$(echo "$resp" | awk '{print $3}')
    body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if detect "$bl_size" "$size" "$bl_status" "$status"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "Baseline: id=$baseline_payload -> ${bl_size}b, id=$payload -> ${size}b" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param: id=$payload (${bl_size}b -> ${size}b)"
      rm -f "$tmpf"; break
    fi
    rm -f "$tmpf"
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "IDOR done: $HIT_COUNT URLs with hits (manual verification required)"
exit "$HIT_COUNT"
