#!/bin/bash
# =============================================================================
# Gospider — crawl URLs using gospider + extracturls.sh
#
# Usage:
#   ./tools/web_gospider.sh <domain>
#   ./tools/web_gospider.sh <domain> <live-file>
#
# Output: <crawl>/gooutput/  →  <crawl>/alivesubsurls.txt
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET="${1:?Usage: $0 <domain> [<live-file>]}"
HTTPS_SUBS="${2:-${RECON_BASE}/$TARGET/subdomains/live_urls.txt}"

OUT_DIR="${RECON_BASE}/$TARGET/crawl"
mkdir -p "$OUT_DIR"

if [ ! -f "$HTTPS_SUBS" ] || [ ! -s "$HTTPS_SUBS" ]; then
  log_err "File not found: $HTTPS_SUBS"
  log_info "Run subdomain_enum.sh first or pass a custom live-urls file"
  exit 1
fi

cp "$HTTPS_SUBS" "$OUT_DIR/https-subs.txt"
NTOTAL=$(wc -l < "$OUT_DIR/https-subs.txt" | tr -d ' ')
log_info "Loaded $NTOTAL live HTTPS URLs"

if ! command -v gospider &>/dev/null; then
  log_err "gospider not found — install via: go install github.com/jaeles-project/gospider@latest"
  exit 1
fi

GO_OUT="$OUT_DIR/gooutput"
rm -rf "$GO_OUT"
log_info "Running gospider ..."
gospider -S "$OUT_DIR/https-subs.txt" -o "$GO_OUT" -c 10 -d 3 -t 20 2>/dev/null

if [ -d "$GO_OUT" ] && [ "$(find "$GO_OUT" -type f 2>/dev/null | wc -l)" -gt 0 ]; then
  # Fast URL extraction — just the grep part (no httpx probing)
  EXCLUDE_EXT="(woff|woff2|ttf|eot|otf|png|svg|jpg|jpeg|gif|ico|bmp|webp|map)(\?.*)?$"
  find "$GO_OUT" -type f -exec cat {} + 2>/dev/null | \
    grep -Eo 'https?://[^ ]+' | \
    grep -i "$TARGET" | \
    grep -viE "$EXCLUDE_EXT" | \
    sed -e 's/[[:space:]]*$//' -e 's:/*$::' | \
    sort -u > "$OUT_DIR/alivesubsurls.txt"
  NGOSPI=$(wc -l < "$OUT_DIR/alivesubsurls.txt" | tr -d ' ')
  if [ "$NGOSPI" -gt 0 ]; then
    log_ok "gospider: $NGOSPI URLs"
    log_info "For httpx probing (slow), run:"
    log_info "  $SCRIPT_DIR/extracturls.sh -f $GO_OUT -d $TARGET"
  else
    log_warn "gospider: no URLs extracted"
  fi
else
  log_warn "gospider produced no output"
fi
