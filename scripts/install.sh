#!/usr/bin/env bash
# =====================================================================
# install.sh — Dristi: Offensive Security MCP — Complete Installer
#
# A single script to install everything:
#   - System dependencies (libpcap, build-essential, etc.)
#   - OpenCode agents, rules, skills
#   - Go CLI security tools (subfinder, nuclei, httpx, ffuf, gf, etc.)
#   - Python tools (awscli, sslyze, etc.)
#   - Cargo tools (feroxbuster)
#   - GF patterns, SecLists wordlists
#   - Playwright Chromium browser
#   - pipx tools
#   - Python virtual environment for the Dristi MCP server
#   - Shell aliases
#
# Idempotent — safe to re-run. Existing config backed up before overwrite.
#
# Usage:
#   bash scripts/install.sh              # Full install
#   bash scripts/install.sh --quick      # Agents + config only, skip tools
# =====================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="$HOME/.dristi/backups/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$HOME/.dristi/install.log"

# ── Parse flags ──────────────────────────────────────────────────────────────
QUICK=false
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=true ;;
  esac
done

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }
header(){ echo -e "\n${BOLD}${B}════════════════════════════════════════${N}"; echo -e "${BOLD}$*${N}"; echo -e "${B}════════════════════════════════════════${N}"; }

mkdir -p "$HOME/.dristi" "$HOME/.config/opencode"
exec > >(tee -a "$LOG_FILE") 2>&1

# ── Platform detection ──────────────────────────────────────────────────────
OS="$(uname -s)"
HAS_SUDO=false
HAS_BREW=false
HAS_CARGO=false
HAS_PASSWORDLESS_SUDO=false
command -v sudo &>/dev/null && HAS_SUDO=true
sudo -n true 2>/dev/null && HAS_PASSWORDLESS_SUDO=true
command -v brew &>/dev/null && HAS_BREW=true
command -v cargo &>/dev/null && HAS_CARGO=true

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
echo "  Repo:      $REPO_DIR"
echo "  Platform:  $OS"
echo "  Log:       $LOG_FILE"
echo "  Mode:      $($QUICK && echo 'quick (agents + config only)' || echo 'full')"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0: Prerequisites
# ══════════════════════════════════════════════════════════════════════════════
header "PHASE 0: Prerequisites"

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
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  ok "uv installed"
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

# ── Quick mode? ─────────────────────────────────────────────────────────────
if $QUICK; then
  info "Quick mode — skipping tool installation"
  warn "Re-run without --quick for full tool setup"
fi

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: System dependencies
# ══════════════════════════════════════════════════════════════════════════════
if ! $QUICK; then
  header "PHASE 1: System dependencies"

  if [ "$OS" = "Linux" ]; then
    if $HAS_PASSWORDLESS_SUDO; then
      info "Installing Linux system packages..."
      sudo apt-get update -qq
      sudo apt-get install -y -qq \
        jq libpcap-dev libssl-dev build-essential pkg-config \
        ca-certificates curl gnupg 2>/dev/null || true
      ok "System packages installed"
    else
      warn "No passwordless sudo — install manually: jq libpcap-dev build-essential"
    fi
  elif [ "$OS" = "Darwin" ] && $HAS_BREW; then
    info "Installing macOS packages..."
    brew install jq libpcap 2>/dev/null || true
    ok "System packages installed"
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 2: Go CLI security tools
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 2: Go security tools"

  GO_TOOLS=(
    # ProjectDiscovery stack
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    # Tomnomnom tools
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/meg@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/qsreplace@latest"
    # Fuzzing / discovery
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/hakluke/hakrevdns@latest"
    # Secrets / analysis
    "github.com/trufflesecurity/trufflehog@latest"
    "github.com/zricethezav/gitleaks/v8@latest"
    "github.com/JohnnyJTH/go-dork@latest"
    # Screenshots
    "github.com/sensepost/gowitness@latest"
    "github.com/michenriksen/aquatone@latest"
    # TLS / infra
    "github.com/lanrat/certgraph@latest"
    "github.com/d3mondev/puredns/v2@latest"
    # OWASP
    "github.com/owasp-amass/amass/v4/...@master"
    # XSS scanner
    "github.com/hahwul/dalfox/v2@latest"
    # DNS
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    # Notify
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    # Uncover
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
  )

  for tool in "${GO_TOOLS[@]}"; do
    raw=$(echo "$tool" | sed 's/@.*//' | sed 's/\/\.\.\.$//')
    name="$(basename "$raw" | sed 's/v[0-9]*$//' | sed 's/v[0-9]*\/cmd\///')"
    # Handle cases like "github.com/OJ/gobuster/v3" -> gobuster
    name="$(echo "$name" | sed 's/^v[0-9]*$//')"
    [ -z "$name" ] && name="$(basename "$(dirname "$raw")")"
    if command -v "$name" &>/dev/null; then
      ok "$name — already installed"
    else
      info "Installing $name..."
      go install "$tool" 2>/dev/null && ok "$name installed" || warn "$name install failed"
    fi
  done

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 3: Python tools (pip)
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 3: Python tools (pip)"

  PIP_TOOLS=(
    "awscli"
    "s3scanner"
    "sslyze"
    "pyjarm"
    "google-play-scraper"
    "androguard"
    "apkleaks"
  )

  for pkg in "${PIP_TOOLS[@]}"; do
    if python3 -c "import importlib.metadata; importlib.metadata.version('$pkg')" 2>/dev/null; then
      ok "$pkg — already installed"
    else
      info "Installing $pkg..."
      if uv pip install --system "$pkg" 2>/dev/null; then
        ok "$pkg installed"
      else
        warn "$pkg install failed"
      fi
    fi
  done

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 4: pipx tools
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 4: pipx tools"

  if ! command -v pipx &>/dev/null; then
    info "Installing pipx..."
    uv tool install pipx 2>/dev/null && ok "pipx installed" || warn "pipx install failed"
    export PATH="$HOME/.local/bin:$PATH"
  fi

  PIPX_TOOLS=(
    "sqlmap"
    "arjun"
    "tldr"
    "cve-search"
  )

  for pkg in "${PIPX_TOOLS[@]}"; do
    if command -v "$pkg" &>/dev/null; then
      ok "$pkg — already installed"
    else
      info "Installing $pkg via pipx..."
      pipx install "$pkg" 2>/dev/null && ok "$pkg installed" || warn "$pkg install failed"
    fi
  done

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 5: Cargo / specialized tools
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 5: Specialized tools"

  # Feroxbuster (cargo or binary)
  if command -v feroxbuster &>/dev/null; then
    ok "feroxbuster — already installed"
  elif $HAS_CARGO; then
    info "Installing feroxbuster (cargo)..."
    cargo install feroxbuster 2>/dev/null && ok "feroxbuster installed" || warn "feroxbuster install failed"
  else
    warn "cargo not available — install feroxbuster manually: cargo install feroxbuster"
  fi

  # GF patterns
  header "Phase 5b: GF patterns"
  GF_PATTERNS_SRC="$REPO_DIR/wordlists/gf-patterns"
  if [ -d "$GF_PATTERNS_SRC" ] && ls "$GF_PATTERNS_SRC"/*.json &>/dev/null 2>&1; then
    mkdir -p "$HOME/.gf"
    cp "$GF_PATTERNS_SRC"/*.json "$HOME/.gf/" 2>/dev/null && \
      ok "GF patterns installed → ~/.gf/ ($(ls "$GF_PATTERNS_SRC"/*.json 2>/dev/null | wc -l) patterns)" || \
      warn "No GF patterns found"
  elif [ -d "$GF_PATTERNS_SRC" ]; then
    info "GF patterns dir exists but empty — skipping"
  else
    info "Cloning GF patterns..."
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns 2>/dev/null
    mkdir -p "$HOME/.gf"
    mv /tmp/Gf-Patterns/*.json "$HOME/.gf/" 2>/dev/null
    rm -rf /tmp/Gf-Patterns
    ok "GF patterns installed → ~/.gf/"
  fi

  # SecLists
  header "Phase 5d: SecLists wordlists"
  SECLISTS="/opt/SecLists"
  if [ -d "$SECLISTS" ]; then
    ok "SecLists found at $SECLISTS"
  elif $HAS_PASSWORDLESS_SUDO; then
    info "Cloning SecLists (~200MB, may take a while)..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists "$SECLISTS" 2>/dev/null && \
      ok "SecLists cloned" || warn "SecLists clone failed"
  fi
fi # end if ! $QUICK

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5e: Python reconnaissance tools (Spoofy, cloud_enum, msftrecon, Scopify)
# ═══════════════════════════════════════════════════════════════════════════════
if ! $QUICK; then
  header "Phase 5e: Python recon tools (Spoofy, cloud_enum, msftrecon, Scopify)"

  INTEL_SCRIPT="$REPO_DIR/scripts/tools/phase-intel.sh"
  if [ -f "$INTEL_SCRIPT" ]; then
    if command -v uv &>/dev/null && command -v git &>/dev/null; then
      info "Installing intel tools via phase-intel.sh..."
      bash "$INTEL_SCRIPT" --install 2>&1 || warn "Some intel tools failed to install (see log)"
    else
      warn "uv or git missing — skip intel tool install"
    fi
  else
    warn "phase-intel.sh not found at $INTEL_SCRIPT"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Playwright Chromium
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 6: Playwright Chromium"

# Install @playwright/mcp globally via npm
if command -v npm &>/dev/null; then
  if ! npm list -g @playwright/mcp &>/dev/null 2>&1; then
    info "Installing @playwright/mcp..."
    npm install -g @playwright/mcp 2>/dev/null && ok "@playwright/mcp installed" || warn "npm install failed"
  else
    ok "@playwright/mcp — already installed"
  fi
fi

# Install Chromium browser for Playwright
if command -v npx &>/dev/null; then
  info "Installing Playwright Chromium browser..."
  npx playwright install chromium 2>/dev/null && ok "Chromium installed for Playwright" || warn "Chromium install failed (try: npx playwright install chromium)"
else
  warn "npx not found — install Chromium manually: npx playwright install chromium"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Dristi MCP server — Python venv
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 7: Dristi MCP server"

if [ -f "$REPO_DIR/server/venv/bin/python" ]; then
  ok "Python venv already exists"
else
  info "Creating Python virtual environment..."
  cd "$REPO_DIR/server"
  rm -rf venv
  uv venv venv
  UV_PROJECT_ENVIRONMENT=venv uv sync
  cd "$REPO_DIR"
  ok "Python venv created + dependencies installed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: OpenCode agents + rules
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 8: OpenCode agents & rules"

OC_AGENTS_DIR="$HOME/.config/opencode/agents"
OC_RULES_DIR="$HOME/.config/opencode/rules"
OC_HOME_AGENTS="$HOME/.opencode/agents"
OC_HOME_RULES="$HOME/.opencode/rules"

mkdir -p "$OC_AGENTS_DIR" "$OC_RULES_DIR" "$OC_HOME_AGENTS" "$OC_HOME_RULES"

# Agents (.opencode/agents/*.md)
if [ -d "$REPO_DIR/.opencode/agents" ]; then
  for agent_file in "$REPO_DIR/.opencode/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    # Symlink to ~/.config/opencode/agents/
    ln -sf "$agent_file" "$OC_AGENTS_DIR/$agent_name"
    # Also to legacy ~/.opencode/agents/
    ln -sf "$agent_file" "$OC_HOME_AGENTS/$agent_name"
  done
  ok "Agents linked ($(ls "$REPO_DIR/.opencode/agents"/*.md 2>/dev/null | wc -l) files)"
fi

# Rules (.opencode/rules/*.md)
if [ -d "$REPO_DIR/.opencode/rules" ]; then
  for rule_file in "$REPO_DIR/.opencode/rules"/*.md; do
    [ -f "$rule_file" ] || continue
    rule_name="$(basename "$rule_file")"
    ln -sf "$rule_file" "$OC_RULES_DIR/$rule_name"
    ln -sf "$rule_file" "$OC_HOME_RULES/$rule_name"
  done
  ok "Rules linked ($(ls "$REPO_DIR/.opencode/rules"/*.md 2>/dev/null | wc -l) files)"
fi

# Commands (.opencode/commands-bughunt/*.md) → ~/.config/opencode/commands/
OC_COMMANDS_DIR="$HOME/.config/opencode/commands"
PROJECT_CMD_DIR="$REPO_DIR/.opencode/commands"
HOME_CMD_DIR="$HOME/.opencode/commands"
mkdir -p "$OC_COMMANDS_DIR" "$PROJECT_CMD_DIR" "$HOME_CMD_DIR"
if [ -d "$REPO_DIR/.opencode/commands-bughunt" ]; then
  for cmd_file in "$REPO_DIR/.opencode/commands-bughunt"/*.md; do
    [ -f "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    cp "$cmd_file" "$OC_COMMANDS_DIR/$cmd_name"
    cp "$cmd_file" "$PROJECT_CMD_DIR/$cmd_name"
    cp "$cmd_file" "$HOME_CMD_DIR/$cmd_name"
  done
  ok "Commands installed ($(ls "$REPO_DIR/.opencode/commands-bughunt"/*.md 2>/dev/null | wc -l) files)"
fi

# Skills symlink (for manual browsing)
DRISTI_SKILLS="$HOME/.dristi/skills"
mkdir -p "$HOME/.dristi"
[ -L "$DRISTI_SKILLS" ] && rm "$DRISTI_SKILLS"
ln -s "$REPO_DIR/skills" "$DRISTI_SKILLS"
ok "Skills linked at $DRISTI_SKILLS"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9: OpenCode config (MCP servers)
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 9: OpenCode MCP configuration"

OPENCODE_CONFIG="$HOME/.config/opencode/opencode.json"

# Backup existing config
if [ -f "$OPENCODE_CONFIG" ]; then
  mkdir -p "$BACKUP_DIR"
  cp "$OPENCODE_CONFIG" "$BACKUP_DIR/opencode.json"
  info "Backed up existing config → $BACKUP_DIR/"
fi

# Build MCP config
export REPO_DIR
# Add nvm Node.js to PATH for npm/npx resolution
export NVM_DIR="$HOME/.nvm"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  \. "$NVM_DIR/nvm.sh" 2>/dev/null
  LATEST_NODE=$(ls "$NVM_DIR/versions/node/" 2>/dev/null | tail -1)
  [ -n "$LATEST_NODE" ] && export PATH="$NVM_DIR/versions/node/$LATEST_NODE/bin:$PATH"
fi

python3 << 'PYEOF'
import json, os, shutil

repo = os.environ['REPO_DIR']
home = os.path.expanduser("~")
config_path = os.path.join(home, ".config", "opencode", "opencode.json")

mcp = {}

# Burp Suite MCP (remote — requires Burp + MCP Server extension running)
mcp["burp"] = {
    "type": "remote",
    "url": "http://127.0.0.1:9876/",
    "enabled": True
}

# WSTG server
mcp["wstg"] = {
    "type": "local",
    "prompt": "You are a Dristi WSTG penetration testing MCP server.",
    "command": [
        "bash",
        "-c",
        f"cd {repo}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run server.py"
    ]
}

# Playwright MCP
playwright_bin = shutil.which("playwright-mcp")
if playwright_bin:
    real = os.path.realpath(playwright_bin)
    node_bin = shutil.which("node") or shutil.which("nodejs") or "/usr/bin/node"
    playwright_args = [node_bin, real]
elif shutil.which("npx"):
    playwright_args = [shutil.which("npx"), "-y", "@playwright/mcp"]
else:
    playwright_args = ["npx", "-y", "@playwright/mcp"]

mcp["playwright"] = {
    "type": "local",
    "command": playwright_args
}

config = {
    "$schema": "https://opencode.ai/config.json",
    "mcp": mcp
}

os.makedirs(os.path.dirname(config_path), exist_ok=True)
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print("[+] Burp MCP configured (SSE :9876)")
print("[+] WSTG MCP server configured")
print("[+] Playwright MCP server configured")
PYEOF

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 10: Shell aliases
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 10: Shell aliases"

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

DRISTI_MARKER="# --- Dristi config ---"
ALIASES="
$DRISTI_MARKER
export DRISTI_HOME=\"$REPO_DIR\"
alias dristi='cd \$DRISTI_HOME'
alias dristi-server='cd \$DRISTI_HOME/server && UV_PROJECT_ENVIRONMENT=venv uv run server.py'
alias dristi-update='cd \$DRISTI_HOME && git pull'
alias dristi-recon='bash \$DRISTI_HOME/scripts/tools/auto_recon.sh'
alias connect-burp='bash \$DRISTI_HOME/scripts/connect-burp.sh'
alias full-hunt='bash \$DRISTI_HOME/scripts/full_hunt.sh'
"

if [ -n "$SHELL_RC" ]; then
  if grep -q "$DRISTI_MARKER" "$SHELL_RC" 2>/dev/null; then
    sed -i "/$DRISTI_MARKER/,/^# --- End Dristi/d" "$SHELL_RC"
  fi
  echo "$ALIASES" >> "$SHELL_RC"
  echo "# --- End Dristi ---" >> "$SHELL_RC"
  ok "Aliases added to $SHELL_RC"
else
  warn "No shell RC found — add aliases manually:"
  echo "$ALIASES"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 11: Verification
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 11: Verification"

# Core tools
if ! $QUICK; then
  info "Checking core tools..."
  for tool in subfinder dnsx httpx nuclei ffuf gf gau katana anew trufflehog gitleaks jq feroxbuster; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool — found"
    else
      warn "$tool — not in PATH"
    fi
  done
fi

# Dristi server venv
if [ -f "$REPO_DIR/server/venv/bin/python" ]; then
  ok "Dristi server venv — ready"
else
  warn "Dristi server venv — missing (run: cd server && uv venv venv && uv sync)"
fi

# Chromium for Playwright
if [ -d "$HOME/.cache/ms-playwright" ]; then
  ok "Playwright Chromium — installed"
else
  warn "Playwright Chromium — not found (run: npx playwright install chromium)"
fi

# OpenCode config
if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config — $OPENCODE_CONFIG"
fi

# GF patterns
GF_COUNT=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l)
[ "$GF_COUNT" -gt 0 ] && ok "GF patterns — $GF_COUNT in ~/.gf/" || warn "GF patterns — none in ~/.gf/"

# ═══════════════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${G}
  ╔══════════════════════════════════════════════════════╗
  ║          Dristi Installation Complete!                 ║
  ╚══════════════════════════════════════════════════════╝${N}"
echo ""
echo "  Commands:   dristi, dristi-server, dristi-update, dristi-recon"
echo "  OpenCode:   opencode  (launches with Dristi pre-configured)"
  echo "  Agents:     87 OpenCode agents"
echo "  Tools:      $($QUICK && echo 'skipped (re-run without --quick)' || echo '50+ security tools')"
echo ""
echo "  Quick start:"
echo "    1. opencode"
echo "    2. /hunt example.com"
echo ""
echo "  Log:      $LOG_FILE"
echo "  Backups:  $BACKUP_DIR"
echo ""
