#!/bin/bash
# =============================================================================
# Automated Nuclei Scanning — templates on live hosts
#
# Runs nuclei against live URLs with tech-matched severity filtering.
#
# Usage:
#   ./tools/auto_nuclei.sh <domain>                  # auto paths under recon/<domain>/crawl/
#   ./tools/auto_nuclei.sh <domain> <live-file>      # custom live URL file
#   ./tools/auto_nuclei.sh <live-file>               # direct file path, domain from path
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

TARGET_RAW="${1:?Usage: $0 <domain> [<live-file>]}"

if [[ "$TARGET_RAW" == -* ]]; then
  TARGET_RAW="${2:?Usage: $0 <domain> [<live-file>]}"
  LIVE_FILE="${3:-}"
else
  LIVE_FILE="${2:-}"
  [[ "$LIVE_FILE" == -* ]] && LIVE_FILE="${3:-}"
fi

if [[ "$TARGET_RAW" == */* ]]; then
  LIVE_FILE="$TARGET_RAW"
  TARGET=$(echo "$TARGET_RAW" | sed -n 's|.*/recon/\([^/]*\)/.*|\1|p')
  [ -z "$TARGET" ] && TARGET="target"
else
  TARGET="$TARGET_RAW"
  [ -z "$LIVE_FILE" ] && LIVE_FILE="$BASE_DIR/recon/$TARGET/subdomains/https-subs.txt"
fi

OUT_DIR="$BASE_DIR/recon/$TARGET/nuclei"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Ensure nuclei is installed ──────────────────────────────────────
if ! command -v nuclei &>/dev/null; then
  log_info "Installing nuclei ..."
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
  log_ok "nuclei installed"
fi

# ── Update templates ────────────────────────────────────────────────
log_info "Updating nuclei templates ..."
nuclei -update-templates 2>/dev/null

# ── Check input ─────────────────────────────────────────────────────
if [ ! -f "$LIVE_FILE" ] || [ ! -s "$LIVE_FILE" ]; then
  log_warn "No live URLs found: $LIVE_FILE"
  log_info "Run subdomain_enum.sh and web_crawl.sh first"
  exit 0
fi

NHOSTS=$(wc -l < "$LIVE_FILE" | tr -d ' ')

# ── Scan critical + high ────────────────────────────────────────────
log_info "Running nuclei on $NHOSTS live hosts (critical + high severity) ..."
nuclei -l "$LIVE_FILE" \
  -severity critical,high \
  -o "$OUT_DIR/nuclei_critical_high.txt" \
  -silent \
  2>/dev/null

CH=$(wc -l < "$OUT_DIR/nuclei_critical_high.txt" 2>/dev/null | tr -d ' ')
log_ok "critical/high: $CH findings"

# ── Scan medium ─────────────────────────────────────────────────────
log_info "Running nuclei on $NHOSTS live hosts (medium severity) ..."
nuclei -l "$LIVE_FILE" \
  -severity medium \
  -o "$OUT_DIR/nuclei_medium.txt" \
  -silent \
  2>/dev/null

M=$(wc -l < "$OUT_DIR/nuclei_medium.txt" 2>/dev/null | tr -d ' ')
log_ok "medium: $M findings"

# ── Tech detection ──────────────────────────────────────────────────
log_info "Running tech-detect ..."
nuclei -l "$LIVE_FILE" \
  -tags tech \
  -o "$OUT_DIR/nuclei_tech.txt" \
  -silent \
  2>/dev/null

T=$(wc -l < "$OUT_DIR/nuclei_tech.txt" 2>/dev/null | tr -d ' ')
log_ok "tech-detect: $T findings"

# ── Summary ─────────────────────────────────────────────────────────
TOTAL=$((CH + M))
log_ok "=== Nuclei Results ==="
log_ok "  critical+high: $CH → $OUT_DIR/nuclei_critical_high.txt"
log_ok "  medium:        $M → $OUT_DIR/nuclei_medium.txt"
log_ok "  tech-detect:   $T → $OUT_DIR/nuclei_tech.txt"
log_ok "  total:         $TOTAL"
log_ok "Done. Results in $OUT_DIR/"
