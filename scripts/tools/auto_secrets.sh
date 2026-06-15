#!/bin/bash
# =============================================================================
# Automated Secrets Validation — verify cariddi findings via curl
#
# Takes cariddi output (URLs) and checks if each path is accessible.
# Confirms high-value paths (.env, .git, config, etc.) + classifies by response.
#
# Usage:
#   ./tools/auto_secrets.sh <domain>
#   ./tools/auto_secrets.sh <domain> --cariddi <cariddi.txt>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--cariddi <cariddi.txt>]}"
CARIDDI_FILE="${3:-${RECON_BASE}/$TARGET/cariddi/cariddi.txt}"
OUT_DIR="${RECON_BASE}/$TARGET/secrets"
mkdir -p "$OUT_DIR"

if [ ! -f "$CARIDDI_FILE" ] || [ ! -s "$CARIDDI_FILE" ]; then
  log_warn "cariddi.txt not found or empty: $CARIDDI_FILE"
  log_info "Run cariddi_scan.sh first"
  exit 0
fi

NURLS=$(wc -l < "$CARIDDI_FILE" | tr -d ' ')

# ── High-value keywords for classification ──────────────────────────
HIGH_VALUE_PATTERNS="\.env|\.git|config\.json|wp-config|backup\.sql|database\.sql|error\.log|laravel\.log|php_errors|credentials|password|secret|api_key|token|\.pem|\.key"

# ── Validate each URL ───────────────────────────────────────────────
log_info "Validating $NURLS cariddi findings via curl ..."
CONFIRMED=0
HIGH_VALUE=0

while IFS= read -r url; do
  [ -z "$url" ] && continue

  code=$(curl -s -L -m 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  size=$(curl -s -L -m 5 -o "$OUT_DIR/.page" -w "%{size_download}" "$url" 2>/dev/null)

  # Classify response
  case "$code" in
    200|204)
      echo "$url -> $code (${size}B)" >> "$OUT_DIR/accessible.txt"
      log_ok "  $code: $url (${size}B)"
      CONFIRMED=$((CONFIRMED + 1))
      if echo "$url" | grep -iqE "$HIGH_VALUE_PATTERNS"; then
        echo "$url -> $code (${size}B)" >> "$OUT_DIR/high_value_confirmed.txt"
        HIGH_VALUE=$((HIGH_VALUE + 1))
        log_ok "  [HIGH VALUE] $url"
      fi
      ;;
    301|302|307|308)
      redirect=$(curl -s -L -m 5 -o /dev/null -w "%{redirect_url}" "$url" 2>/dev/null)
      echo "$url -> $code → $redirect" >> "$OUT_DIR/redirects.txt"
      log_ok "  $code: $url → $redirect"
      ;;
    401|403)
      echo "$url -> $code" >> "$OUT_DIR/forbidden.txt"
      log_warn "  $code: $url (exists but restricted)"
      CONFIRMED=$((CONFIRMED + 1))
      ;;
    404)
      echo "$url -> 404" >> "$OUT_DIR/not_found.txt"
      ;;
    *)
      echo "$url -> $code" >> "$OUT_DIR/other.txt"
      ;;
  esac
done < "$CARIDDI_FILE"

rm -f "$OUT_DIR/.page"

# ── Summary ─────────────────────────────────────────────────────────
log_ok "=== Secrets Validation ==="
log_ok "  accessible:  $(wc -l < "$OUT_DIR/accessible.txt" 2>/dev/null | tr -d ' ') → $OUT_DIR/accessible.txt"
log_ok "  high-value:  $(wc -l < "$OUT_DIR/high_value_confirmed.txt" 2>/dev/null | tr -d ' ') → $OUT_DIR/high_value_confirmed.txt"
log_ok "  forbidden:   $(wc -l < "$OUT_DIR/forbidden.txt" 2>/dev/null | tr -d ' ') → $OUT_DIR/forbidden.txt"
log_ok "  redirects:   $(wc -l < "$OUT_DIR/redirects.txt" 2>/dev/null | tr -d ' ') → $OUT_DIR/redirects.txt"
log_ok "  not found:   $(wc -l < "$OUT_DIR/not_found.txt" 2>/dev/null | tr -d ' ') → 404s"
log_ok "Done. Results in $OUT_DIR/"
