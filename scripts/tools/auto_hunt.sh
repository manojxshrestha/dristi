#!/bin/bash
# auto_hunt.sh - full recon + hunt pipeline

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

[ $# -eq 0 ] && { echo "Usage: $0 <domain> [--skip xss,sqli,nuclei,secrets]" >&2; exit 1; }
TARGET="$1"
SKIP_ARRAY=()
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --skip)
            IFS=',' read -ra SKIP_ARRAY <<< "$2"
            shift 2
            ;;
        *)
            log_err "Unknown option: $1"
            exit 1
            ;;
    esac
done

skip() {
    for s in "${SKIP_ARRAY[@]}"; do
        [ "$s" = "$1" ] && return 0
    done
    return 1
}

trap 'log_warn "Interrupted by user"; exit 130' INT

# source auth helper if present
AUTH_HELPER="$SCRIPT_DIR/_auth_helper.sh"
if [ -f "$AUTH_HELPER" ]; then
    # shellcheck source=./_auth_helper.sh
    source "$AUTH_HELPER"
    bb_auth_banner
fi

START_TS=$(date +%s)
log_info "Auto Hunt for: $TARGET"
echo ""

run_phase() {
    local name="$1"
    local script="$2"
    [ ! -x "$script" ] && { log_warn "$script not found or not executable, skipping $name"; return 1; }
    log_info "=== $name ==="
    bash "$script" "$TARGET"
    echo ""
}

run_phase "Phase 0-3: Recon" "$SCRIPT_DIR/auto_recon.sh"

skip xss || run_phase "Phase 4: XSS" "$SCRIPT_DIR/auto_xss.sh"
skip sqli || run_phase "Phase 5: SQLi" "$SCRIPT_DIR/auto_sqli.sh"
skip nuclei || run_phase "Phase 6: Nuclei" "$SCRIPT_DIR/auto_nuclei.sh"
skip secrets || run_phase "Phase 7: Secrets" "$SCRIPT_DIR/auto_secrets.sh"

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
log_ok "Auto Hunt Complete"
log_ok "Results: $BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-rea-group-bb-001}/recon/$TARGET/"
log_ok "Time: $((ELAPSED / 60))m $((ELAPSED % 60))s"
