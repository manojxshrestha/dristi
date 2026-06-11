#!/usr/bin/env bash
# reconnect-burp.sh — Burp Suite MCP Bridge Reconnection Helper
#
# Walks through:
#   1. Kill stale WSL-side MCP proxy
#   2. Check Windows port 9876 (Burp MCP SSE endpoint)
#   3. If nothing listening, guide user to start Burp + MCP server
#   4. Test connectivity via nc / curl
#   5. Toggle opencode.json to force reconnection
#   6. Restart WSTG MCP server (in background)
#
# Usage: bash scripts/reconnect-burp.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

DST="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$HOME/.config/opencode/opencode.json"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }

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

# ── Step 1: Kill stale WSL-side proxy ─────────────────────────────────────────
info "Checking for stale MCP proxy processes..."
STALE_PIDS=$(pgrep -f "mcp-proxy-all" 2>/dev/null || true)
if [ -n "$STALE_PIDS" ]; then
  kill $STALE_PIDS 2>/dev/null || true
  sleep 1
  ok "Killed stale MCP proxy: PID $STALE_PIDS"
else
  ok "No stale proxy found"
fi

# Also kill any orphaned Dristi WSTG server
WSTG_PIDS=$(pgrep -f "uv run server.py" 2>/dev/null || true)
if [ -n "$WSTG_PIDS" ]; then
  kill $WSTG_PIDS 2>/dev/null || true
  info "Stopped existing WSTG server (PID $WSTG_PIDS) — will restart"
fi

# ── Step 2: Check port 9876 on Windows ────────────────────────────────────────
info "Checking port 9876 on Windows..."
LISTEN_PID=""

if [ -x "/mnt/c/Windows/System32/netstat.exe" ]; then
  NETSTAT_OUT=$(/mnt/c/Windows/System32/netstat.exe -ano 2>/dev/null | grep ":9876" | grep LISTENING || true)
  LISTEN_PID=$(echo "$NETSTAT_OUT" | awk '{print $NF}' | tr -d '\r' | head -1 || true)
fi

if [ -n "$LISTEN_PID" ]; then
  # Verify PID is still alive
  if [ -x "/mnt/c/Windows/System32/tasklist.exe" ]; then
    TASK_INFO=$(/mnt/c/Windows/System32/tasklist.exe //FI "PID eq $LISTEN_PID" 2>/dev/null | grep "$LISTEN_PID" || true)
    if [ -n "$TASK_INFO" ]; then
      PROC_NAME=$(echo "$TASK_INFO" | awk '{print $1}')
      ok "Port 9876 — PID $LISTEN_PID ($PROC_NAME)"
    else
      warn "Port 9876 is orphaned (PID $LISTEN_PID no longer exists)"
      echo ""
      echo "  From Windows Admin cmd:"
      echo "    netstat -ano | findstr :9876"
      echo "    taskkill /PID $LISTEN_PID /F          # port 9876"
      echo ""
      LISTEN_PID=""
    fi
  else
    ok "Port 9876 — PID $LISTEN_PID"
  fi
fi

if [ -z "$LISTEN_PID" ]; then
  err "Nothing listening on port 9876"
  echo ""
  echo "  To fix:"
  echo "    1. Start Burp Suite on Windows"
  echo "    2. Extensions → MCP Server → Enable"
  echo "    3. Verify: curl -s http://127.0.0.1:9876"
  echo ""
  echo "  From Windows Admin cmd:"
  echo "    netstat -ano | findstr :9876"
  echo "    taskkill /PID <PID> /F"
  echo "    Run: taskkill /PID 8452 /F"
  echo ""
  echo "  Then re-run this script."
  exit 1
fi

# ── Step 3: Test TCP connectivity ──────────────────────────────────────────────
info "Testing TCP connection to 127.0.0.1:9876..."
if command -v nc &>/dev/null; then
  if nc -z -w3 127.0.0.1 9876 2>/dev/null; then
    ok "TCP port 9876 — accepting connections"
  else
    err "Port 9876 is listening but not accepting connections"
    echo "  Try: Restart Burp MCP server (Extensions → MCP → Disable → Enable)"
    exit 1
  fi
elif command -v curl &>/dev/null; then
  if curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://127.0.0.1:9876 2>/dev/null | grep -q .; then
    ok "Port 9876 responds"
  else
    warn "curl to port 9876 failed — but netstat shows it listening, continuing..."
  fi
fi

# ── Step 4: Toggle opencode.json to force reconnection ─────────────────────────
info "Toggling Burp MCP entry in opencode config..."
if [ ! -f "$CONFIG" ]; then
  err "OpenCode config not found at $CONFIG"
  echo "  Run 'bash scripts/setup.sh' first to set up the config."
  exit 1
fi

python3 << 'PYEOF'
import json, os, sys

config_path = os.path.expanduser("~/.config/opencode/opencode.json")
backup_path = config_path + ".bak"

try:
    with open(config_path) as f:
        cfg = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"[-] Cannot read config: {e}")
    sys.exit(1)

burp = cfg.get("mcp", {}).get("burp")
if not burp:
    print("[-] No 'burp' entry in opencode MCP config")
    print("    Run 'bash scripts/setup.sh' to configure it.")
    sys.exit(1)

# Back up
with open(backup_path, "w") as f:
    json.dump(cfg, f, indent=2)

# Remove and re-add to trigger reconnection
del cfg["mcp"]["burp"]
with open(config_path, "w") as f:
    json.dump(cfg, f, indent=2)

cfg["mcp"]["burp"] = burp
with open(config_path, "w") as f:
    json.dump(cfg, f, indent=2)

print("[+] Burp MCP entry toggled — OpenCode should reconnect")
PYEOF

# ── Step 5: Restart WSTG MCP server ────────────────────────────────────────────
info "Starting Dristi WSTG MCP server (background)..."
nohup bash -c "cd '$DST/server' && UV_PROJECT_ENVIRONMENT=venv exec uv run server.py" \
  > "$HOME/.dristi/server.log" 2>&1 &
WSTG_PID=$!
sleep 2

if kill -0 "$WSTG_PID" 2>/dev/null; then
  ok "WSTG MCP server started (PID $WSTG_PID)"
else
  warn "WSTG MCP server failed to start — check: cat ~/.dristi/server.log"
fi

# ── Step 6: Verify ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${G}
╔══════════════════════════════════════╗
║     Reconnection Complete              ║
╚══════════════════════════════════════╝${N}"
echo ""
echo "  In OpenCode TUI:"
echo "    1. Check MCP panel — both should show as connected"
echo "    2. burp  — HTTP/1.1 + HTTP/2 requests, scanner, intruder"
echo "    3. wstg  — 94-tool pentest MCP server"
echo ""
echo "  Troubleshooting:"
echo "    ~/.dristi/server.log  — WSTG server log"
echo "    Burp Suite → Extensions → MCP → check status"
echo ""
