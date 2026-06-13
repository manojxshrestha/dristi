#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# setup.sh — Dristi config refresh
#
# Lightweight — refreshes agent symlinks, commands, rules, and shell aliases.
# Run install.sh first for full tool installation + MCP config.
#
# What this script does:
#   - Checks prerequisites (go, python3, git, curl, uv, opencode)
#   - Verifies Python venv exists
#   - Symlinks OpenCode agents, commands, rules
#   - Adds shell aliases
#   - Verifies installation state
#
# What it does NOT do (use install.sh instead):
#   - Install Go/Python/cargo security tools
#   - Clone GF patterns or SecLists
#   - Create or overwrite opencode.json (MCP config)
#   - Install Playwright Chromium
#   - Install system packages (apt/brew)
#
# Idempotent — safe to re-run.
# Usage:  bash scripts/setup.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

DST="$(cd "$(dirname "$0")/.." && pwd)"
OPENCODE_CONFIG="$HOME/.config/opencode/opencode.json"
BACKUP_DIR="$HOME/.dristi/backups/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$HOME/.dristi/install.log"

# ── Color output ──────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }
header(){ echo -e "\n${BOLD}${B}════════════════════════════════════════${N}"; echo -e "${BOLD}$*${N}"; echo -e "${B}════════════════════════════════════════${N}"; }

mkdir -p "$HOME/.dristi" "$HOME/.config/opencode"

exec > >(tee -a "$LOG_FILE") 2>&1

# ── Platform detection ────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
print_banner() {
    echo -e "${BOLD}${C}
    .___      .__          __  .__
  __| _/______|__| _______/  |_|__|
 / __ |\_  __ \  |/  ___/\   __\  |
/ /_/ | |  | \/  |\___ \  |  | |  |
\____ | |__|  |__/____  > |__| |__|
     \/               \/
         by ~/.manojxshrestha${N}"
}
print_banner
echo "  Target:    $DST"
echo "  Platform:  $OS / $ARCH"
echo "  Log:       $LOG_FILE"
echo ""

# Check prerequisites
for cmd in go python3 git curl; do
  if ! command -v "$cmd" &>/dev/null; then
    err "$cmd not found — install it first"
    case "$cmd" in
      go) echo "  https://go.dev/dl/" ;;
      python3) echo "  https://www.python.org/downloads/" ;;
      *) echo "  apt install $cmd || brew install $cmd" ;;
    esac
    exit 1
  fi
done

# Install uv if missing
if ! command -v uv &>/dev/null; then
  info "uv not found — installing..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
fi

# Install OpenCode if missing
if ! command -v opencode &>/dev/null; then
  info "OpenCode not found — installing..."
  curl -fsSL https://opencode.ai/install.sh | bash
  export PATH="$HOME/.opencode/bin:$PATH"
  ok "OpenCode installed"
else
  ok "OpenCode — already installed ($(opencode --version 2>/dev/null || echo 'unknown'))"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Dristi MCP server — verify venv exists
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 1: Dristi MCP server"

if [ -f "$DST/server/venv/bin/python" ]; then
  ok "Python venv ready"
else
  warn "Python venv missing — run install.sh first (or: cd server && uv venv venv && uv sync)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: OpenCode config — verify, don't overwrite
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 2: OpenCode configuration"

if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config exists — not modifying"
else
  warn "OpenCode config not found — run install.sh first to generate it"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: OpenCode agents, rules, commands, skills
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 3: OpenCode agents, rules"

OC_AGENTS_DIR="$HOME/.config/opencode/agents"
mkdir -p "$OC_AGENTS_DIR" "$HOME/.config/opencode/rules"

# Agents (flat .md files)
if [ -d "$DST/.opencode/agents" ]; then
  for agent_file in "$DST/.opencode/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    target="$OC_AGENTS_DIR/$agent_name"
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$agent_file" ]; then
      ok "Agent $agent_name — already linked"
    else
      ln -sf "$agent_file" "$target"
      ok "Agent $agent_name — linked"
    fi
  done
fi

# Legacy home-level agent links
OC_HOME_AGENTS="$HOME/.opencode/agents"
mkdir -p "$OC_HOME_AGENTS"
if [ -d "$DST/.opencode/agents" ]; then
  for agent_file in "$DST/.opencode/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    target="$OC_HOME_AGENTS/$agent_name"
    ln -sf "$agent_file" "$target"
  done
fi

# Rules
if [ -d "$DST/.opencode/rules" ]; then
  for rule_file in "$DST/.opencode/rules"/*.md; do
    [ -f "$rule_file" ] || continue
    rule_name="$(basename "$rule_file")"
    target="$HOME/.config/opencode/rules/$rule_name"
    ln -sf "$rule_file" "$target"
    ok "Rule $rule_name — linked"
  done
fi

# Commands (.opencode/commands-bughunt/*.md) → all 3 locations
if [ -d "$DST/.opencode/commands-bughunt" ]; then
  OC_CMD_DIR="$HOME/.config/opencode/commands"
  PROJECT_CMD_DIR="$DST/.opencode/commands"
  HOME_CMD_DIR="$HOME/.opencode/commands"
  mkdir -p "$OC_CMD_DIR" "$PROJECT_CMD_DIR" "$HOME_CMD_DIR"
  for cmd_file in "$DST/.opencode/commands-bughunt"/*.md; do
    [ -f "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    cp "$cmd_file" "$OC_CMD_DIR/$cmd_name"
    cp "$cmd_file" "$PROJECT_CMD_DIR/$cmd_name"
    cp "$cmd_file" "$HOME_CMD_DIR/$cmd_name"
    ok "Command $cmd_name — installed"
  done
fi

# Skills symlink (for manual browse)
SKILLS_LINK="$HOME/.dristi/skills"
mkdir -p "$HOME/.dristi"
[ -L "$SKILLS_LINK" ] && rm "$SKILLS_LINK"
ln -s "$DST/skills" "$SKILLS_LINK"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Shell aliases
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 4: Shell aliases"

SHELL_RC=""
if [ -n "${ZDOTDIR:-}" ] && [ -f "$ZDOTDIR/.zshrc" ]; then
  SHELL_RC="$ZDOTDIR/.zshrc"
elif [ -f "$HOME/.zshrc" ]; then
  SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
  SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
  SHELL_RC="$HOME/.bash_profile"
fi

DRISTI_CONFIG_MARKER="# --- Dristi config ---"
ALIASES="
$DRISTI_CONFIG_MARKER
export DRISTI_HOME=\"$DST\"
alias dristi='cd \$DRISTI_HOME'
alias dristi-server='cd \$DRISTI_HOME/server && UV_PROJECT_ENVIRONMENT=venv uv run server.py'
alias dristi-update='cd \$DRISTI_HOME && git pull'
alias dristi-recon='bash \$DRISTI_HOME/scripts/tools/auto_recon.sh'
alias connect-burp='bash \$DRISTI_HOME/scripts/connect-burp.sh'
alias full-hunt='bash \$DRISTI_HOME/scripts/full_hunt.sh'
"

if [ -n "$SHELL_RC" ]; then
  if grep -q "$DRISTI_CONFIG_MARKER" "$SHELL_RC" 2>/dev/null; then
    sed -i "/$DRISTI_CONFIG_MARKER/,/^# --- End Dristi/d" "$SHELL_RC"
  fi
  echo "$ALIASES" >> "$SHELL_RC"
  echo "# --- End Dristi ---" >> "$SHELL_RC"
  ok "Aliases added to $SHELL_RC"
else
  warn "No shell RC found — add these manually:"
  echo "$ALIASES"
fi

eval "$ALIASES" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Verification
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 5: Verification"

# Dristi server venv
if [ -f "$DST/server/venv/bin/python" ]; then
  ok "Dristi server venv — ready"
else
  err "Dristi server venv — missing (run install.sh first)"
fi

# OpenCode config
if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config — $OPENCODE_CONFIG"
else
  warn "OpenCode config — not found"
fi

# GF patterns (installed by install.sh, verify here)
GF_COUNT=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l)
if [ "$GF_COUNT" -gt 0 ]; then
  ok "GF patterns — $GF_COUNT patterns in ~/.gf/"
else
  warn "GF patterns — none found in ~/.gf/ (run install.sh)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${G}
  ╔══════════════════════════════════════════════════════╗
  ║           Dristi Setup Complete!                      ║
  ╚══════════════════════════════════════════════════════╝${N}"
echo ""
echo "  Aliases refreshed:"
echo "    dristi              — cd to project root"
echo "    dristi-server       — Start the WSTG MCP server"
echo "    dristi-recon        — Run auto_recon.sh"
echo "    connect-burp        — Connect/reconnect Burp MCP bridge"
echo "    full-hunt <target>  — Run automated recon pipeline"
echo ""
echo "  OpenCode:"
echo "    opencode            — Launch OpenCode with Dristi"
echo ""
echo "  To install tools: bash scripts/install.sh"
echo ""
echo "  Log: $LOG_FILE"
echo "  Backups: $BACKUP_DIR"
echo ""
