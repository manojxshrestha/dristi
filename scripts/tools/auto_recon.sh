#!/bin/bash
# =============================================================================
# Auto Recon Pipeline — full recon for a target domain
#
# Runs the entire reconnaissance pipeline in sequence:
#   1. Subdomain enumeration (passive)  → subdomain_enum.sh
#   2. Web crawling                     → web_crawl.sh
#   3. Parameter extraction + GF        → param_extract.sh
#   4. Cariddi secrets/info scan        → cariddi_scan.sh
#   5. DNS brute-force                  → dns_bruteforce.sh
#   6. Vhost fuzzing                    → vhost_fuzz.sh
#   7. Directory brute-force            → dir_bruteforce.sh
#   8. Zone transfer check              → zone_transfer.sh
#   9. GitHub dorking                   → github_dork.sh
#
# Usage:
#   ./tools/auto_recon.sh <domain>
#   ./tools/auto_recon.sh <domain> --skip dns,github
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain> [--skip dns,github]}"
SKIP=""
if [ "${2:-}" = "--skip" ] && [ -n "${3:-}" ]; then
  IFS=',' read -ra SKIP_LIST <<< "$3"
  for s in "${SKIP_LIST[@]}"; do SKIP="$SKIP,$s"; done
fi

skip() { [[ "$SKIP" == *",$1"* ]]; }

# ── Global timeout: 30 minutes per phase ────────────────────────────
PHASE_TIMEOUT=${PHASE_TIMEOUT:-1800}

START_TS=$(date +%s)
log_info "=== Auto Recon for: $TARGET ==="
echo ""

# ── 1. Subdomain Enumeration ────────────────────────────────────────
if ! skip "subdomains"; then
  log_info "=== Phase 1: Subdomain Enumeration ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/subdomain_enum.sh" "$TARGET" || log_warn "Phase 1 (subdomains) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 2. DNS Brute-force ──────────────────────────────────────────────
if ! skip "dns"; then
  log_info "=== Phase 2: DNS Brute-force ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/dns_bruteforce.sh" "$TARGET" || log_warn "Phase 2 (dns) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 3. Web Crawling ─────────────────────────────────────────────────
if ! skip "crawl"; then
  log_info "=== Phase 3: Web Crawling ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/web_crawl.sh" "$TARGET" || log_warn "Phase 3 (crawl) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 4. Parameter Extraction ─────────────────────────────────────────
if ! skip "params"; then
  log_info "=== Phase 4: Parameter Extraction ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/param_extract.sh" "$TARGET" || log_warn "Phase 4 (params) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 5. Cariddi Scan ─────────────────────────────────────────────────
if ! skip "cariddi"; then
  log_info "=== Phase 5: Cariddi Scan ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/cariddi_scan.sh" "$TARGET" || log_warn "Phase 5 (cariddi) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 6. Vhost Fuzzing ────────────────────────────────────────────────
if ! skip "vhost"; then
  log_info "=== Phase 6: Vhost Fuzzing ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/vhost_fuzz.sh" "$TARGET" || log_warn "Phase 6 (vhost) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 7. Directory Brute-force ────────────────────────────────────────
if ! skip "dir"; then
  log_info "=== Phase 7: Directory Brute-force ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/dir_bruteforce.sh" "$TARGET" || log_warn "Phase 7 (dir) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 8. Zone Transfer ────────────────────────────────────────────────
if ! skip "zone"; then
  log_info "=== Phase 8: Zone Transfer Check ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/zone_transfer.sh" "$TARGET" || log_warn "Phase 8 (zone) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 9. GitHub Dorking ───────────────────────────────────────────────
if ! skip "github"; then
  log_info "=== Phase 9: GitHub Dorking ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/github_dork.sh" "$TARGET" || log_warn "Phase 9 (github) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

# ── 10. S3 / Cloud Bucket Scan ──────────────────────────────────────
if ! skip "s3"; then
  log_info "=== Phase 10: S3 / Cloud Bucket Scan ==="
  timeout "$PHASE_TIMEOUT" bash "$SCRIPT_DIR/s3_buckets.sh" "$TARGET" || log_warn "Phase 10 (s3) timed out after ${PHASE_TIMEOUT}s"
  echo ""
fi

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

log_ok "=== Auto Recon Complete ==="
log_ok "Results in: $BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/"
log_ok "Elapsed: ${MINS}m ${SECS}s"
