#!/usr/bin/env bash
# =============================================================================
# Phase 4: RECON — Subdomains, crawling, parameter extraction, secrets
#
# Usage: ./tools/phase-recon.sh <domain> [output_dir]
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log_info "=== Phase 4: Full Reconnaissance ==="

# 1. Subdomain enumeration
if [ -f "$SCRIPT_DIR/subdomain_enum.sh" ]; then
  log_info "Subdomain enumeration..."
  bash "$SCRIPT_DIR/subdomain_enum.sh" "$TARGET" || log_warn "Subdomain enum had issues"
fi

# 2. Web crawling
if [ -f "$SCRIPT_DIR/web_waymore.sh" ]; then
  log_info "Web crawl (waymore)..."
  bash "$SCRIPT_DIR/web_waymore.sh" "$TARGET" || log_warn "waymore had issues"
fi
if [ -f "$SCRIPT_DIR/web_gospider.sh" ]; then
  log_info "Web crawl (gospider)..."
  bash "$SCRIPT_DIR/web_gospider.sh" "$TARGET" || log_warn "gospider had issues"
fi
if [ -f "$SCRIPT_DIR/web_katana.sh" ]; then
  log_info "Web crawl (katana)..."
  bash "$SCRIPT_DIR/web_katana.sh" "$TARGET" || log_warn "katana had issues"
fi

# 3. Merge crawl output
CRAWL_DIR="$OUT_DIR/crawl"
if ls "$CRAWL_DIR"/*.txt &>/dev/null 2>&1; then
  log_info "Merging crawl output..."
  cat "$CRAWL_DIR"/*.txt 2>/dev/null | sort -u > "$CRAWL_DIR/merged-crawl.txt" 2>/dev/null || true
  cp "$CRAWL_DIR/merged-crawl.txt" "$CRAWL_DIR/crawledurls.txt" 2>/dev/null || true
fi

# 4. Run full auto_recon.sh if it exists (handles the rest: params, nuclei, cariddi, dns, vhost, dirbust)
if [ -f "$SCRIPT_DIR/auto_recon.sh" ]; then
  log_info "Auto recon pipeline..."
  bash "$SCRIPT_DIR/auto_recon.sh" "$TARGET" --skip "" || log_warn "auto_recon had issues"
fi

log_ok "Phase 4 (recon) complete"
log_info "Output in: $OUT_DIR"
