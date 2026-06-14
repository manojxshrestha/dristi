#!/bin/bash
# =============================================================================
# Batch Subdomain Enumeration — parallel execution across multiple domains
#
# Runs subdomain_enum.sh for multiple domains in parallel with job control.
# Each domain gets its own subdomain_enum.sh process.
#
# Usage:
#   ./tools/batch_subdomain_enum.sh -f domains.txt          # file, one domain per line
#   ./tools/batch_subdomain_enum.sh example.com test.com    # inline domains
#   ./tools/batch_subdomain_enum.sh -j 4 -f domains.txt     # 4 concurrent jobs
#
# Options:
#   -f <file>    File with domains (one per line)
#   -j <num>     Max concurrent jobs (default: 3)
#   -h           Show help
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

MAX_JOBS=3
DOMAINS_FILE=""
DOMAINS=()

while getopts "f:j:h" opt; do
  case "$opt" in
    f) DOMAINS_FILE="$OPTARG" ;;
    j) MAX_JOBS="$OPTARG" ;;
    h)
      echo "Usage: $0 [-j <jobs>] -f <domains-file>"
      echo "       $0 [-j <jobs>] domain1 domain2 domain3"
      exit 0
      ;;
    *) exit 1 ;;
  esac
done
shift $((OPTIND - 1))

if [ -n "$DOMAINS_FILE" ]; then
  if [ ! -f "$DOMAINS_FILE" ]; then
    log_err "File not found: $DOMAINS_FILE"
    exit 1
  fi
  mapfile -t DOMAINS < <(grep -v '^\s*$\|^\s*#' "$DOMAINS_FILE" | tr -d ' ')
elif [ $# -gt 0 ]; then
  DOMAINS=("$@")
else
  log_err "No domains specified. Use -f <file> or pass domains as arguments."
  exit 1
fi

TOTAL=${#DOMAINS[@]}
log_info "Enumerating $TOTAL domain(s) with $MAX_JOBS concurrent job(s):"
for d in "${DOMAINS[@]}"; do
  echo "  - $d"
done
echo ""

FAILED=()
RESULTS=()

run_enum() {
  local domain="$1"
  local idx="$2"
  local out_file="$BASE_DIR/recon/$domain/subdomains/batch-status.txt"

  mkdir -p "$BASE_DIR/recon/$domain/subdomains"
  echo "started" > "$out_file"

  bash "$SCRIPT_DIR/subdomain_enum.sh" "$domain" 2>&1
  local exit_code=$?

  if [ $exit_code -eq 0 ]; then
    if [ -f "$BASE_DIR/recon/$domain/subdomains/https-subs.txt" ]; then
      local count
      count=$(wc -l < "$BASE_DIR/recon/$domain/subdomains/https-subs.txt" | tr -d ' ')
      echo "done:$count" > "$out_file"
      echo "[$idx/$TOTAL] $domain — OK ($count live URLs)"
    else
      echo "done:0" > "$out_file"
      echo "[$idx/$TOTAL] $domain — OK (0 live)"
    fi
  else
    echo "failed" > "$out_file"
    echo "[$idx/$TOTAL] $domain — FAILED (exit $exit_code)" >&2
  fi

  return $exit_code
}

PID_LIST=()
JOB_COUNT=0
ACTIVE=0

for i in "${!DOMAINS[@]}"; do
  domain="${DOMAINS[$i]}"
  idx=$((i + 1))

  # Wait if at max jobs
  while [ "$ACTIVE" -ge "$MAX_JOBS" ]; do
    for pid_idx in "${!PID_LIST[@]}"; do
      pid="${PID_LIST[$pid_idx]}"
      if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        unset "PID_LIST[$pid_idx]"
        ACTIVE=$((ACTIVE - 1))
      fi
    done
    PID_LIST=("${PID_LIST[@]}")
    [ "$ACTIVE" -ge "$MAX_JOBS" ] && sleep 1
  done

  run_enum "$domain" "$idx" &
  PID_LIST+=($!)
  ACTIVE=$((ACTIVE + 1))
done

# Wait for remaining jobs
for pid in "${PID_LIST[@]}"; do
  wait "$pid" 2>/dev/null || true
done

# Collect results
echo ""
log_info "=== Batch Results ==="
LIVE_TOTAL=0
for domain in "${DOMAINS[@]}"; do
  status_file="$BASE_DIR/recon/$domain/subdomains/batch-status.txt"
  if [ -f "$status_file" ]; then
    status=$(cat "$status_file")
    case "$status" in
      done:*)
        count="${status#done:}"
        LIVE_TOTAL=$((LIVE_TOTAL + count))
        log_ok "  $domain — $count live URLs"
        ;;
      failed|started)
        log_err "  $domain — FAILED"
        FAILED+=("$domain")
        ;;
    esac
  else
    log_warn "  $domain — no output"
    FAILED+=("$domain")
  fi
done

echo ""
log_ok "Completed: $((TOTAL - ${#FAILED[@]}))/$TOTAL domains"
log_ok "Total live URLs across all domains: $LIVE_TOTAL"
if [ ${#FAILED[@]} -gt 0 ]; then
  log_warn "Failed: ${#FAILED[@]} domain(s): ${FAILED[*]}"
fi
