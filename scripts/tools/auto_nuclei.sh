#!/bin/bash
# auto_nuclei.sh - run nuclei on live hosts

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

[ $# -lt 1 ] && { echo "Usage: $0 <domain> [<live-file>]" >&2; exit 1; }

TARGET=""
LIVE_FILE=""

if [[ "$1" == */* ]]; then
    # first arg looks like a path
    LIVE_FILE="$1"
    # try to extract domain from recon path
    TARGET=$(echo "$LIVE_FILE" | sed -n 's|.*/recon/\([^/]*\)/.*|\1|p')
    [ -z "$TARGET" ] && TARGET="unknown"
else
    TARGET="$1"
    LIVE_FILE="${2:-${RECON_BASE}/$TARGET/subdomains/https-subs.txt}"
fi

OUT_DIR="${RECON_BASE}/$TARGET/nuclei"
mkdir -p "$OUT_DIR"
LOG_FILE="$OUT_DIR/nuclei.log"

trap 'log_warn "Interrupted"; exit 130' INT

if ! command -v nuclei &>/dev/null; then
    log_err "nuclei not found — install via: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

log_info "Updating templates..."
nuclei -update-templates 2>>"$LOG_FILE" || log_warn "template update failed"

if [ ! -f "$LIVE_FILE" ] || [ ! -s "$LIVE_FILE" ]; then
    log_warn "No live URLs: $LIVE_FILE"
    log_info "Run subdomain_enum.sh and auto_recon.sh first"
    exit 0
fi

NHOSTS=$(wc -l < "$LIVE_FILE" | tr -d ' ')

run_nuclei() {
    local severity="$1"
    local outfile="$2"
    local extra="$3"
    log_info "Scanning $NHOSTS hosts ($severity) ..."
    nuclei -l "$LIVE_FILE" -severity "$severity" $extra \
        -o "$outfile" -silent 2>>"$LOG_FILE"
    local cnt=$(wc -l < "$outfile" 2>/dev/null | tr -d ' ')
    echo "$cnt"
}

# critical+high
CH=$(run_nuclei "critical,high" "$OUT_DIR/nuclei_critical_high.txt" "")
log_ok "critical/high: $CH"

# medium
M=$(run_nuclei "medium" "$OUT_DIR/nuclei_medium.txt" "")
log_ok "medium: $M"

# tech detection
T=$(run_nuclei "info,low,medium,high,critical" "$OUT_DIR/nuclei_tech.txt" "-tags tech")
log_ok "tech-detect: $T"

TOTAL=$((CH + M))
log_ok "=== Results ==="
log_ok "critical+high: $CH → $OUT_DIR/nuclei_critical_high.txt"
log_ok "medium:        $M → $OUT_DIR/nuclei_medium.txt"
log_ok "tech:          $T → $OUT_DIR/nuclei_tech.txt"
log_ok "total:         $TOTAL (critical+high+medium)"
log_ok "Log: $LOG_FILE"
