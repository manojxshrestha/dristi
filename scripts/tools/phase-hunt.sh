#!/usr/bin/env bash
# =============================================================================
# Phase 6: HUNT — Vulnerability hunting dispatcher
#
# Usage: ./tools/phase-hunt.sh <domain> [output_dir]
#
# This phase runs the automated scanners and prepares findings for AI analysis.
# The AI agent (@hunt) should be called separately to analyze results.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HUNT_DIR="$OUT_DIR/hunt"
mkdir -p "$HUNT_DIR"

log_info "=== Phase 6: Vulnerability Hunting ==="

# 1. Parameter extraction + fuzzing
if [ -f "$SCRIPT_DIR/param_extract.sh" ]; then
  log_info "Parameter extraction..."
  bash "$SCRIPT_DIR/param_extract.sh" "$TARGET" || log_warn "param_extract had issues"
fi
if [ -f "$SCRIPT_DIR/param_discovery.sh" ]; then
  log_info "Parameter discovery (fuzzing)..."
  bash "$SCRIPT_DIR/param_discovery.sh" "$TARGET" || log_warn "param_discovery had issues"
fi

# 3. Secrets hunting
if [ -f "$SCRIPT_DIR/secrets_hunter.sh" ]; then
  log_info "Secrets hunting..."
  bash "$SCRIPT_DIR/secrets_hunter.sh" "$TARGET" || log_warn "secrets_hunter had issues"
fi
if [ -f "$SCRIPT_DIR/auto_secrets.sh" ]; then
  bash "$SCRIPT_DIR/auto_secrets.sh" "$TARGET" || true
fi

# 4. SQLi automation
if [ -f "$SCRIPT_DIR/auto_sqli.sh" ]; then
  log_info "SQLi scanning..."
  bash "$SCRIPT_DIR/auto_sqli.sh" "$TARGET" || log_warn "SQLi scan had issues"
fi

# 5. XSS automation
if [ -f "$SCRIPT_DIR/auto_xss.sh" ]; then
  log_info "XSS scanning..."
  bash "$SCRIPT_DIR/auto_xss.sh" "$TARGET" || log_warn "XSS scan had issues"
fi

# 6. Directory bruteforce
if [ -f "$SCRIPT_DIR/dir_bruteforce.sh" ]; then
  log_info "Directory bruteforce..."
  bash "$SCRIPT_DIR/dir_bruteforce.sh" "$TARGET" || log_warn "dir bruteforce had issues"
fi

# 7. Vhost fuzzing
if [ -f "$SCRIPT_DIR/vhost_fuzz.sh" ]; then
  log_info "VHost fuzzing..."
  bash "$SCRIPT_DIR/vhost_fuzz.sh" "$TARGET" || log_warn "vhost fuzz had issues"
fi

# 8. 403 bypass
if [ -f "$SCRIPT_DIR/bypass_403.sh" ]; then
  log_info "403 bypass checks..."
  bash "$SCRIPT_DIR/bypass_403.sh" "$TARGET" --quick || log_warn "403 bypass had issues"
fi

log_ok "All automated hunt scripts completed"
log_info "Review findings in: $OUT_DIR (subdirs: params/, secrets/, sqli/, xss/, directories/, vhost/)"
log_info "Then call @hunt agent for AI-driven analysis of results"
log_ok "Phase 6 (hunt) complete"
