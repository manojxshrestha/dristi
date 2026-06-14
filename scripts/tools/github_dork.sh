#!/bin/bash
# =============================================================================
# GitHub Dorking — automated secret scanning via gh CLI
#
# Runs Gdorklinks.sh queries programmatically through GitHub's search API.
# Skips gracefully if gh is not logged in or unavailable.
#
# Usage:
#   ./tools/github_dork.sh <company-name>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET="${1:?Usage: $0 <company-name>}"
WITHOUT_SUFFIX="${TARGET%%.*}"

# ── Check gh auth ───────────────────────────────────────────────────
if ! command -v gh &>/dev/null; then
  log_warn "gh CLI not found — skipping GitHub dorking"
  exit 0
fi

if ! gh auth status 2>/dev/null | grep -q "Logged in"; then
  log_warn "gh not logged in — skipping GitHub dorking"
  exit 0
fi

OUT_DIR="$BASE_DIR/recon/$TARGET/github_dorks"
mkdir -p "$OUT_DIR"
RESULTS="$OUT_DIR/findings.txt"

# ── Dork queries ────────────────────────────────────────────────────
QUERIES=(
  "password"
  "npmrc _auth"
  "dockercfg"
  "pem private"
  "id_rsa"
  "aws_access_key_id"
  "s3cfg"
  "htpasswd"
  "git-credentials"
  "bashrc password"
  "SECRET_KEY"
  "client_secret"
  "github_token"
  "api_key"
  "app_secret"
  "passwd"
  "credentials"
  "secrets"
  ".env"
)

# Also search without suffix (e.g., "company" if "company.com")
NAMES=("$TARGET" "$WITHOUT_SUFFIX")

log_info "Running GitHub dorks on '$TARGET'..."

for name in "${NAMES[@]}"; do
  [ -z "$name" ] && continue
  log_info "Searching: \"$name\""

  for query in "${QUERIES[@]}"; do
    gh search code "\"$name\" $query" \
      --limit 10 \
      --json repository,path,url \
      -q '.[] | "\(.repository.nameWithOwner):\(.path) -> \(.url)"' \
      2>/dev/null >> "$RESULTS"

    gh search code "\"$name\" filename:$query" \
      --limit 10 \
      --json repository,path,url \
      -q '.[] | "\(.repository.nameWithOwner):\(.path) -> \(.url)"' \
      2>/dev/null >> "$RESULTS"
  done
done

# ── Output ──────────────────────────────────────────────────────────
if [ -s "$RESULTS" ]; then
  sort -u "$RESULTS" -o "$RESULTS"
  COUNT=$(wc -l < "$RESULTS" | tr -d ' ')
  log_ok "Found $COUNT potential hits"
  log_info "Results saved to $RESULTS"
  echo ""
  head -50 "$RESULTS"
  [ "$COUNT" -gt 50 ] && log_info "... and $(($COUNT - 50)) more (see $RESULTS)"
else
  log_ok "No results found"
fi
