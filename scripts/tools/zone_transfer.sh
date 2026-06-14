#!/bin/bash
# =============================================================================
# Zone Transfer (AXFR) Check
#
# Enumerates NS records for a domain and attempts a full zone transfer
# against each nameserver. A misconfigured DNS server will dump the
# entire zone — subdomains, IPs, mail servers, internal hostnames.
#
# Usage:
#   ./tools/zone_transfer.sh <domain>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="$BASE_DIR/runtime/engagements/${ENGAGEMENT_ID:-rea-group-bb-001}/recon/$TARGET/zone_transfer"
mkdir -p "$OUT_DIR"

# ── Step 1: Enumerate NS records ────────────────────────────────────
log_info "Enumerating NS records for $TARGET..."
NS_SERVERS=$(dig NS "$TARGET" +short 2>/dev/null)

if [ -z "$NS_SERVERS" ]; then
  log_err "No NS records found for $TARGET"
  exit 1
fi

echo "$NS_SERVERS" | tee "$OUT_DIR/ns_servers.txt"
log_ok "Found $(echo "$NS_SERVERS" | wc -l | tr -d ' ') nameserver(s)"

# ── Step 2: Attempt AXFR against each NS ────────────────────────────
FOUND=0
while IFS= read -r ns; do
  # Remove trailing dot if present
  ns="${ns%.}"
  log_info "Attempting zone transfer against $ns ..."

  RESULT=$(dig axfr @"$ns" "$TARGET" 2>/dev/null)

  if echo "$RESULT" | grep -qi "Transfer failed\|timed out\|connection refused\|SERVFAIL\|REFUSED\|NXDOMAIN"; then
    log_warn "  $ns - Transfer failed (secured)"
  elif [ -z "$RESULT" ] || ! echo "$RESULT" | grep -q "IN"; then
    log_warn "  $ns - No zone data returned"
  else
    log_ok "  $ns - ZONE TRANSFER SUCCESSFUL!"
    echo "$RESULT" > "$OUT_DIR/${ns}_axfr.txt"
    log_ok "  Saved to $OUT_DIR/${ns}_axfr.txt"
    FOUND=$((FOUND + 1))
  fi
done <<< "$NS_SERVERS"

# ── Summary ─────────────────────────────────────────────────────────
if [ "$FOUND" -gt 0 ]; then
  log_ok "Zone transfer succeeded on $FOUND nameserver(s)! Check $OUT_DIR/"
else
  log_warn "All nameservers are secured — no zone transfer possible."
fi
