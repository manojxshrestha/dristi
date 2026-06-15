#!/usr/bin/env bash
# =============================================================================
# Phase 5: SURFACE — Classify endpoints, prioritize attack surface
#
# Usage: ./tools/phase-surface.sh <domain> [output_dir]
#
# Output: $OUT_DIR/surface/endpoint_map_ranked.txt
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

SURFACE_DIR="$OUT_DIR/surface"
mkdir -p "$SURFACE_DIR"

log_info "Analyzing recon output for $TARGET..."

# Collect all known URLs
URL_FILE="$SURFACE_DIR/all_urls.txt"
: > "$URL_FILE"

for src in "$OUT_DIR/crawl/merged-crawl.txt" "$OUT_DIR/subdomains/live_urls.txt" \
           "$OUT_DIR/crawl/crawledurls.txt" "$OUT_DIR/crawl/cleansubskatanaurls.txt" \
           "$OUT_DIR/crawl/waygauurls.txt" "$OUT_DIR/crawl/alivesubsurls.txt"; do
  if [ -f "$src" ]; then
    cat "$src" >> "$URL_FILE" 2>/dev/null || true
  fi
done

sort -u "$URL_FILE" -o "$URL_FILE"
TOTAL_URLS=$(wc -l < "$URL_FILE")
log_ok "Collected $TOTAL_URLS unique URLs"

# Classify by tier
TIER0="$SURFACE_DIR/tier0_public_input.txt"
TIER1="$SURFACE_DIR/tier1_auth_input.txt"
TIER2="$SURFACE_DIR/tier2_infra.txt"

: > "$TIER0"
: > "$TIER1"
: > "$TIER2"

if [ "$TOTAL_URLS" -gt 0 ]; then
  while IFS= read -r url; do
    case "$url" in
      *login*|*signin*|*auth*|*oauth*|*saml*|*logout*|*register*|*signup*)
        echo "$url" >> "$TIER1" ;;
      *admin*|*api*|*graphql*|*swagger*|*v1/*|*v2/*|*rest/*)
        echo "$url" >> "$TIER1" ;;
      *.js|*.json|*.xml|*.yaml|*.conf|*.bak|*.old|*robots.txt|*sitemap.xml|*.git/*|*.env*)
        echo "$url" >> "$TIER0" ;;
      *)
        echo "$url" >> "$TIER2" ;;
    esac
  done < "$URL_FILE"
fi

TIER0_COUNT=$(wc -l < "$TIER0" 2>/dev/null || echo 0)
TIER1_COUNT=$(wc -l < "$TIER1" 2>/dev/null || echo 0)
TIER2_COUNT=$(wc -l < "$TIER2" 2>/dev/null || echo 0)

# Build ranked map
{
  echo "=== Endpoint Map (Ranked) ==="
  echo "Target: $TARGET"
  echo "Total URLs: $TOTAL_URLS"
  echo ""
  echo "--- Tier 0: Public + Input (test first) ---"
  cat "$TIER0"
  echo ""
  echo "--- Tier 1: Auth + Input ---"
  cat "$TIER1"
  echo ""
  echo "--- Tier 2: Infrastructure / Info ---"
  head -50 "$TIER2"
  echo "  ... ($TIER2_COUNT total in tier 2)"
} > "$SURFACE_DIR/endpoint_map_ranked.txt"

log_ok "Surface analysis: Tier0=$TIER0_COUNT Tier1=$TIER1_COUNT Tier2=$TIER2_COUNT"
log_ok "Phase 5 (surface) complete — ranked map at $SURFACE_DIR/endpoint_map_ranked.txt"
