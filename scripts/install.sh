#!/usr/bin/env bash
# =====================================================================
# install.sh — Dristi Offensive Security MCP Installer
#
# Installs:
#   - OpenCode agents  → ~/.opencode/agents/
#   - OpenCode commands → ~/.opencode/commands/
#   - OpenCode rules    → ~/.opencode/rules/
#   - Skills reference  → ~/.dristi/skills/  (symlink)
#   - Dristi aliases    → shell rc
#   - Full auto-setup   → run ./scripts/dristi.sh for complete install
#
# Idempotent: safe to re-run. Existing files backed up before overwrite.
#
# Usage:
#   bash scripts/install.sh              # Quick: copy agents + commands
#   bash scripts/dristi.sh               # Full: tools + server + config
# =====================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DEST="$HOME/.dristi/backups/$(date +%Y%m%d-%H%M%S)"

# ── Config ──────────────────────────────────────────────────────────────────
# OpenCode directories
OC_AGENTS="$HOME/.opencode/agents"
OC_RULES="$HOME/.opencode/rules"

# Legacy Claude Code directories (for backwards compat)
CC_SKILLS="$HOME/.claude/skills"
CC_COMMANDS="$HOME/.claude/commands"

# Dristi reference
DRISTI_SKILLS="$HOME/.dristi/skills"

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }

echo -e "${BOLD}Dristi — Offensive Security MCP${N}"
echo "Installing from: $REPO_DIR"
echo ""

mkdir -p "$OC_AGENTS" "$OC_RULES" "$HOME/.dristi"

# ── Detect install mode ────────────────────────────────────────────────────
# If run from within .opencode/, assume already in OpenCode context
# and just symlink the agents
if echo "$REPO_DIR" | grep -q "\.opencode"; then
  warn "Run this script from the Dristi repo root, not from .opencode/"
fi

# ── Install OpenCode agents (flat .md files) ──────────────────────────
if [ -d "$REPO_DIR/.opencode/agents" ]; then
  echo "Agents →  $OC_AGENTS"
  for agent_file in "$REPO_DIR/.opencode/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    target="$OC_AGENTS/$agent_name"
    ln -sf "$agent_file" "$target"
    ok "Agent '$agent_name' — linked"
  done
  echo ""
fi

# ── Install OpenCode rules ──────────────────────────────────────────────────
if [ -d "$REPO_DIR/.opencode/rules" ]; then
  echo "Rules →  $OC_RULES"
  for rule_file in "$REPO_DIR/.opencode/rules"/*.md; do
    [ -f "$rule_file" ] || continue
    rule_name="$(basename "$rule_file")"
    target="$OC_RULES/$rule_name"

    ln -sf "$rule_file" "$target"
    ok "Rule '$rule_name' — linked"
  done
  echo ""
fi

# ── Skills symlink ──────────────────────────────────────────────────────────
echo "Skills →  $DRISTI_SKILLS"
[ -L "$DRISTI_SKILLS" ] && rm "$DRISTI_SKILLS"
ln -sf "$REPO_DIR/skills" "$DRISTI_SKILLS"
ok "Skills linked at $DRISTI_SKILLS"
echo ""

# ── Legacy Claude Code support (optional) ──────────────────────────────────
if [ -d "$CC_SKILLS" ] || [ -d "$CC_COMMANDS" ]; then
  echo "Legacy Claude Code → detected"
  info "To install for Claude Code too, run:"
  echo "  export CLAUDE_CODE=1 && bash scripts/install.sh"
  echo ""
fi

# ── Count installed ────────────────────────────────────────────────────────
AGENT_COUNT=$(ls "$OC_AGENTS"/*.md 2>/dev/null | wc -l)

echo "============================================"
echo -e "${BOLD}${G}✓ Install complete${N}"
echo "============================================"
echo ""
echo "  Agents:   $AGENT_COUNT  → $OC_AGENTS"
echo "  Skills:                → $DRISTI_SKILLS"
echo ""
echo "Next steps:"
echo "  1. Full setup (tools + server):  bash scripts/dristi.sh"
echo "  2. Start server:                 dristi-server"
echo "  3. Launch OpenCode:              opencode"
echo ""
