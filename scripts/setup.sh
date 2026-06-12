#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# setup.sh — Dristi: Offensive Security MCP platform auto-setup
#
# What this script does:
#   - Installs Go/Python/cargo security tools if missing
#   - Sets up Python venv + deps for the Dristi MCP server
#   - Symlinks OpenCode agents, commands, rules
#   - Installs GF patterns + SecLists
#   - Adds shell aliases
#
# What YOU need to do separately:
#   - Install Burp Suite Community/Pro + MCP Server extension
#   - Install OpenCode (if not present, script handles it)
#
# Idempotent — safe to re-run. Backs up existing configs.
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
HAS_SUDO=false
HAS_BREW=false
HAS_CARGO=false
HAS_PASSWORDLESS_SUDO=false
command -v sudo &>/dev/null && HAS_SUDO=true
sudo -n true 2>/dev/null && HAS_PASSWORDLESS_SUDO=true
command -v brew &>/dev/null && HAS_BREW=true
command -v cargo &>/dev/null && HAS_CARGO=true

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
# PHASE 1: System dependencies
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 1: System dependencies"

if [ "$OS" = "Linux" ]; then
  if $HAS_PASSWORDLESS_SUDO; then
    info "Installing Linux system packages..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
      jq libpcap-dev libssl-dev build-essential pkg-config \
      chromium-browser 2>/dev/null || true
    ok "System packages installed"
  else
    warn "No passwordless sudo — skipping system packages (install jq, libpcap-dev manually)"
  fi
elif [ "$OS" = "Darwin" ] && $HAS_BREW; then
  info "Installing macOS packages..."
  brew install jq libpcap 2>/dev/null || true
  ok "System packages installed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Go security tools
# ═══════════════════════════════════════════════════════════════════════════════
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
  # Fuzzing / discovery
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/OJ/gobuster/v3@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/lc/subjs@latest"
  "github.com/jaeles-project/gospider@latest"
  "github.com/hakluke/hakrawler@latest"
  # Secrets / analysis
  "github.com/trufflesecurity/trufflehog@latest"
  "github.com/zricethezav/gitleaks/v8@latest"
  # Screenshots
  "github.com/sensepost/gowitness@latest"
  "github.com/michenriksen/aquatone@latest"
  # TLS / infra
  "github.com/lanrat/certgraph@latest"
  "github.com/d3mondev/puredns/v2@latest"
  # OWASP
  "github.com/owasp-amass/amass/v4/...@master"
  # Dalfox (XSS scanner)
  "github.com/hahwul/dalfox/v2@latest"
)

for tool in "${GO_TOOLS[@]}"; do
  name="$(basename "$(echo "$tool" | sed 's/@.*//' | sed 's/\/\.\.\.$//' | sed 's/v[0-9]*\/cmd\///' | sed 's/v[0-9]*$//')")"
  if command -v "$name" &>/dev/null; then
    ok "$name — already installed"
  else
    info "Installing $name..."
    go install "$tool" 2>/dev/null && ok "$name installed" || warn "$name install failed"
  fi
done

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Python tools
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 3: Python tools"

PY_TOOLS=(
  "awscli"
  "s3scanner"
  "sslyze"
  "pyjarm"
  "google-play-scraper"
  "androguard"
  "apkleaks"
)

for pkg in "${PY_TOOLS[@]}"; do
  if python3 -c "import importlib.metadata; importlib.metadata.version('$pkg')" 2>/dev/null; then
    ok "$pkg — already installed"
  else
    info "Installing $pkg..."
    if pip3 install -q --user --break-system-packages "$pkg" 2>/dev/null; then
      ok "$pkg installed"
    else
      warn "$pkg install failed (try: pip3 install --user --break-system-packages $pkg)"
    fi
  fi
done

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Other tools (cargo, git clone)
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 4: Specialized tools"

# Feroxbuster (cargo)
if command -v feroxbuster &>/dev/null; then
  ok "feroxbuster — already installed"
elif $HAS_CARGO; then
  info "Installing feroxbuster (cargo)..."
  cargo install feroxbuster 2>/dev/null && ok "feroxbuster installed" || warn "feroxbuster install failed"
else
  warn "cargo not available — install feroxbuster manually: cargo install feroxbuster"
fi

# GF patterns
header "Phase 4b: GF patterns"
GF_PATTERNS_SRC="$DST/wordlists/gf-patterns"
if [ -d "$GF_PATTERNS_SRC" ] && [ "$(ls -A "$GF_PATTERNS_SRC"/*.json 2>/dev/null)" ]; then
  mkdir -p "$HOME/.gf"
  cp "$GF_PATTERNS_SRC"/*.json "$HOME/.gf/" 2>/dev/null && ok "GF patterns installed → ~/.gf/ ($(ls "$GF_PATTERNS_SRC"/*.json 2>/dev/null | wc -l) patterns)" || warn "No GF patterns found in wordlists/"
elif [ -d "$GF_PATTERNS_SRC" ]; then
  info "GF patterns dir exists but empty — skipping"
else
  info "Cloning GF patterns..."
  git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns 2>/dev/null
  mkdir -p "$HOME/.gf"
  mv /tmp/Gf-Patterns/*.json "$HOME/.gf/" 2>/dev/null
  rm -rf /tmp/Gf-Patterns
  ok "GF patterns installed → ~/.gf/"
fi

# SecLists wordlist directory
SECLISTS="/opt/SecLists"
if [ -d "$SECLISTS" ]; then
  ok "SecLists found at $SECLISTS"
elif $HAS_PASSWORDLESS_SUDO; then
  info "Cloning SecLists (~200MB, may take a while)..."
  sudo git clone --depth 1 https://github.com/danielmiessler/SecLists "$SECLISTS" 2>/dev/null && ok "SecLists cloned" || warn "SecLists clone failed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Dristi MCP server setup
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 5: Dristi MCP server"

if [ -f "$DST/server/venv/bin/python" ]; then
  ok "Python venv already exists"
else
  info "Creating Python virtual environment..."
  cd "$DST/server"
  rm -rf venv
  uv venv venv
  UV_PROJECT_ENVIRONMENT=venv uv sync
  cd "$DST"
  ok "Python venv created + dependencies installed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: OpenCode config (agents, commands, rules, MCP)
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 6: OpenCode configuration"

# Backup existing config
if [ -f "$OPENCODE_CONFIG" ]; then
  mkdir -p "$BACKUP_DIR"
  cp "$OPENCODE_CONFIG" "$BACKUP_DIR/opencode.json"
  info "Backed up existing config → $BACKUP_DIR/"
fi

# Build OpenCode MCP config (WSTG server + Playwright only — Burp is user-managed)
info "Creating OpenCode config..."

export DST
# Add nvm Node.js to PATH if available (for npx/playwright-mcp resolution)
export NVM_DIR="$HOME/.nvm"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  \. "$NVM_DIR/nvm.sh" 2>/dev/null
  LATEST_NODE=$(ls "$NVM_DIR/versions/node/" 2>/dev/null | tail -1)
  [ -n "$LATEST_NODE" ] && export PATH="$NVM_DIR/versions/node/$LATEST_NODE/bin:$PATH"
fi
# Install @playwright/mcp globally if node is available
if command -v npm &>/dev/null; then
  if ! npm list -g @playwright/mcp &>/dev/null; then
    info "Installing @playwright/mcp globally..."
    npm install -g @playwright/mcp 2>/dev/null && ok "@playwright/mcp installed" || warn "npm install @playwright/mcp failed"
  else
    ok "@playwright/mcp — already installed"
  fi
fi
python3 << 'PYEOF'
import json, os

dst = os.environ['DST']
home = os.path.expanduser("~")
config_path = os.path.join(home, ".config", "opencode", "opencode.json")

mcp = {}

mcp["wstg"] = {
    "type": "local",
    "prompt": "You are a Dristi WSTG penetration testing MCP server. 96 WSTG tests across 13 categories. Workflow per category: get_wstg_test() for methodology + payloads -> execute via Burp -> log_finding() -> create_exploitation_queue() -> get_technique_guide() -> exploit -> mark_exploited(). track_test() for coverage. get_coverage() before generate_report().",
    "command": [
        "bash",
        "-c",
        f"cd {dst}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run server.py"
    ]
}

import shutil, os
playwright_bin = shutil.which("playwright-mcp")
if playwright_bin:
    # Resolve symlink to get the real script path (playwright-mcp -> ../lib/node_modules/@playwright/mcp/cli.js)
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

print("[+] WSTG MCP server configured")
print("[+] Playwright MCP server configured")
print("[!] Burp MCP not configured — install Burp Suite + MCP Server extension manually")
PYEOF

# Symlink Dristi agents into OpenCode directories
header "Phase 6b: OpenCode agents, rules"
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

# Legacy home-level agent links (flat .md)
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

# Commands (.opencode/commands-bughunt/*.md)
if [ -d "$DST/.opencode/commands-bughunt" ]; then
  OC_CMD_DIR="$HOME/.config/opencode/commands"
  mkdir -p "$OC_CMD_DIR"
  for cmd_file in "$DST/.opencode/commands-bughunt"/*.md; do
    [ -f "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    ln -sf "$cmd_file" "$OC_CMD_DIR/$cmd_name"
    ok "Command $cmd_name — linked"
  done
fi

# Skills directory (for manual browse)
SKILLS_LINK="$HOME/.dristi/skills"
mkdir -p "$HOME/.dristi"
[ -L "$SKILLS_LINK" ] && rm "$SKILLS_LINK"
ln -s "$DST/skills" "$SKILLS_LINK"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Shell configuration
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 7: Shell aliases"

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
alias reconnect-burp='bash \$DRISTI_HOME/scripts/reconnect-burp.sh'
alias full-hunt='bash \$DRISTI_HOME/scripts/full_hunt.sh'
alias dristi-server='cd \$DRISTI_HOME/server && UV_PROJECT_ENVIRONMENT=venv uv run server.py'
alias dristi-update='cd \$DRISTI_HOME && git pull'
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
# PHASE 8: Verify installation
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 8: Verification"

# Core tools
info "Checking core tools..."
CORE_TOOLS=(subfinder dnsx httpx nuclei ffuf gf gau katana anew trufflehog gitleaks jq)
for tool in "${CORE_TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    ok "$tool — $(command -v "$tool")"
  else
    warn "$tool — not in PATH"
  fi
done

# Dristi server
if [ -f "$DST/server/venv/bin/python" ]; then
  ok "Dristi server venv — ready"
else
  err "Dristi server venv — missing (run: cd server && uv venv venv && uv sync)"
fi

# OpenCode config
if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config — $OPENCODE_CONFIG"
else
  warn "OpenCode config — not found"
fi

# GF patterns
GF_COUNT=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l)
if [ "$GF_COUNT" -gt 0 ]; then
  ok "GF patterns — $GF_COUNT patterns in ~/.gf/"
else
  warn "GF patterns — none found in ~/.gf/"
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
echo "  Commands available:"
echo "    dristi              — cd to Dristi project root"
echo "    dristi-server       — Start the WSTG MCP server"
echo "    reconnect-burp      — Reconnect Burp MCP bridge"
echo "    full-hunt <target>  — Run automated recon pipeline"
echo ""
echo "  OpenCode:"
echo "    opencode            — Launch OpenCode with Dristi"
echo ""
echo "  Burp MCP setup:"
echo "    1. Install Burp Suite (Community/Pro)"
echo "    2. Install MCP Server extension from BApp Store"
echo "    3. Configure in opencode.json:"
echo "       \"burp\": { \"type\": \"local\", \"command\": [\"java\", \"-jar\", \"<mcp-proxy-jar>\", \"--sse-url\", \"http://127.0.0.1:9876\"] }"
echo ""
echo "  Model recommendation:"
echo -e "  ${BOLD}Switch to deepseek-v4-flash-free for best results with Dristi agents.${N}"
echo ""
echo "  Log: $LOG_FILE"
echo "  Backups: $BACKUP_DIR"
echo ""
