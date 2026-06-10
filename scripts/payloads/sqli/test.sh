#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=sqli; PAYLOADS="$SCRIPT_DIR/payloads.txt"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [urls-file] [max-payloads]}"
URLS_FILE="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/sqli.txt}"
MAX="${3:-200}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
[ ! -f "$PAYLOADS" ] && err "Missing $PAYLOADS" && exit 1
[ ! -f "$URLS_FILE" ] && err "Missing $URLS_FILE" && exit 1
pat_ref "sqli"

detect() {
  local body="$1" status="$2" duration="$3"
  local -a keywords=(
    "SQL syntax" "mysql_fetch" "mysql_num_rows" "mysql_error"
    "You have an error in your SQL" "Unclosed quotation mark"
    "Warning.*mysql_" "ODBC SQL Server Driver" "SQLite3::"
    "ORA-[0-9][0-9][0-9][0-9]" "Oracle.*Driver" "Microsoft OLE DB"
    "PostgreSQL.*ERROR" "WARN.*PG::" "psql:FATAL"
    "Division by zero" "Fatal error"
    "Incorrect syntax near" "Syntax error in string"
    "Microsoft.*Database Error" "Data type mismatch"
    "DB2 SQL error" "SQLSTATE" "driver.*does not exist"
  )
  for kw in "${keywords[@]}"; do echo "$body" | grep -qi "$kw" 2>/dev/null && return 0; done
  [ "$(echo "$duration" | cut -d. -f1)" -ge 5 ] && return 0
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
    status=$(echo "$resp" | awk '{print $1}')
    duration=$(echo "$resp" | awk '{print $2}')
    body=$(cat "$tmpf" 2>/dev/null || true); rm -f "$tmpf"
    if detect "$body" "$status" "$duration"; then
      local_hits=1; safe=$(echo "$url" | sed 's|https\?://||;s/[^a-zA-Z0-9]/_/g')
      echo "[$status] $payload" >> "$HITS_DIR/${safe}_${param}.txt"
      log "HIT on $param: ${payload:0:60}"
      break  # stop on first hit for this URL
    fi
    TOTAL=$((TOTAL + 1))
  done < "$PAYLOADS"
  [ "$local_hits" -eq 1 ] && HIT_COUNT=$((HIT_COUNT + 1))
done < "$URLS_FILE"
log "SQLi done: $HIT_COUNT URLs with hits"
exit "$HIT_COUNT"
