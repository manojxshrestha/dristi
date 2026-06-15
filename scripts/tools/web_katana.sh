#!/bin/bash
# =============================================================================
# Katana — crawl URLs using katana
#
# Usage:
#   ./tools/web_katana.sh <domain>
#   ./tools/web_katana.sh <domain> <live-file>
#
# Output: <crawl>/cleansubskatanaurls.txt
# =============================================================================

set -uo pipefail

source "$(dirname "$0")/_env.sh"

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

if ! command -v katana &>/dev/null; then
  log_info "Installing katana ..."
  go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null
fi

log_info "Running katana ..."
cat "$OUT_DIR/https-subs.txt" | katana -d 3 -jc -timeout 15 -c 20 2>/dev/null | anew "$OUT_DIR/cleansubskatanaurls.txt"
NKAT=$(wc -l < "$OUT_DIR/cleansubskatanaurls.txt" 2>/dev/null | tr -d ' ' || echo 0)
NKAT=${NKAT:-0}
if [ "$NKAT" -le 2 ]; then
  log_warn "katana: $NKAT URLs (likely CF-blocked)"
else
  log_ok "katana: $NKAT URLs"
fi
