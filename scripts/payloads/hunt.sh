#!/bin/bash
# hunt.sh — Master payload-based vulnerability hunting pipeline
# Usage: ./hunt.sh <engagement-id> [--quick|--deep]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [--quick|--deep]}"
MODE="${2:-quick}"
true  # placeholder

RECON_DIR="$BASE_DIR/runtime/engagements/$ENGAGEMENT/recon"
URLS_DIR="$RECON_DIR/urls"
HITS_DIR="$RECON_DIR/hits"
LIVE_FILE="$RECON_DIR/live.txt"

log()  { echo -e "\033[0;32m[+]\033[0m $1"; }
info() { echo -e "\033[0;36m[*]\033[0m $1"; }
warn() { echo -e "\033[1;33m[!]\033[0m $1"; }
err()  { echo -e "\033[0;31m[-]\033[0m $1"; }

mkdir -p "$URLS_DIR" "$HITS_DIR"

if [ ! -f "$LIVE_FILE" ]; then
  err "No live.txt found at $LIVE_FILE — run recon first"
  exit 1
fi

# ── Phase 1: gf filter live.txt into class-specific URL lists ────────────
info "Phase 1: Filtering live.txt by GF patterns..."
declare -A GF_CLASSES=(
  [sqli]="sqli"
  [xss]="xss"
  [ssti]="ssti"
  [ssrf]="ssrf"
  [cmdi]="cmdi"
  [lfi]="lfi"
  [redirect]="redirect"
  [idor]="idor"
  [xxe]="xxe"
)

for class in "${!GF_CLASSES[@]}"; do
  gf "${GF_CLASSES[$class]}" "$LIVE_FILE" 2>/dev/null > "$URLS_DIR/$class.txt" || true
  count=$(wc -l < "$URLS_DIR/$class.txt" 2>/dev/null || echo 0)
  [ "$count" -gt 0 ] && info "  $class: $count URLs" || true
done

# Additional non-gf classes — use live.txt directly
for class in cors crlf nosqli clickjacking http-param-pollution mass-assignment prototype-pollution; do
  cp "$LIVE_FILE" "$URLS_DIR/$class.txt" 2>/dev/null || true
done

# ── Phase 2: Run payload tests ──────────────────────────────────────────
info "Phase 2: Running PAT payload tests..."
declare -A PAYLOAD_CLASSES=(
  [sqli]="sqli"
  [xss]="xss"
  [ssrf]="ssrf"
  [ssti]="ssti"
  [cmdi]="cmdi"
  [lfi]="lfi"
  [redirect]="redirect"
  [cors]="cors"
  [xxe]="xxe"
  [crlf]="crlf"
  [idor]="idor"
  [nosqli]="nosqli"
  [clickjacking]="clickjacking"
  [prototype-pollution]="prototype-pollution"
  [http-param-pollution]="http-param-pollution"
  [mass-assignment]="mass-assignment"
)

TOTAL_HITS=0
for class in "${!PAYLOAD_CLASSES[@]}"; do
  url_file="$URLS_DIR/$class.txt"
  [ ! -f "$url_file" ] && continue
  [ "$(wc -l < "$url_file" 2>/dev/null || echo 0)" -eq 0 ] && continue

  test_script="$SCRIPT_DIR/$class/test.sh"
  if [ ! -f "$test_script" ]; then
    warn "No test script for $class at $test_script"
    continue
  fi

  info "Testing $class..."
  set +e
  if [ "$MODE" = "deep" ]; then
    bash "$test_script" "$ENGAGEMENT" "$url_file" 5000
  else
    bash "$test_script" "$ENGAGEMENT" "$url_file" 100
  fi
  HITS=$?
  set -e

  if [ "$HITS" -gt 0 ]; then
    TOTAL_HITS=$((TOTAL_HITS + HITS))
    log "$class: $HITS hit(s)"

    true  # nuclei scan removed
  else
    info "  $class: no hits"
  fi
done

# ── Dependency Confusion (special — scan-based, not URL-based) ──────────
info "Testing dependency-confusion (package file scan)..."
set +e
bash "$SCRIPT_DIR/dependency-confusion/test.sh" "$ENGAGEMENT"
set -e

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
log "═══════════════════════════════════════════════════════"
log " HUNT COMPLETE for $ENGAGEMENT"
log " Mode: $MODE"
for class in "${!PAYLOAD_CLASSES[@]}"; do
  dir="$HITS_DIR/$class"
  if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null | wc -l)" -gt 0 ]; then
    log "  $class: $(ls "$dir" | wc -l) endpoint(s) with hits"
  fi
done
log "═══════════════════════════════════════════════════════"
echo ""
info "Hits saved to: $RECON_DIR/hits/<class>/"
info "To verify manually:"
info "  cat $RECON_DIR/hits/<class>/*.txt"
info "Next: review hits and test manually"
