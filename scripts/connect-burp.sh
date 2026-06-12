#!/usr/bin/env bash
# connect-burp.sh — Burp MCP connection helper
#
# 1. Check Burp MCP on Windows (port 9876) — user must have Burp running
# 2. Deploy & start Windows Python proxy (port 9872) — rewrites Host + strips Origin
# 3. Verify the proxy chain works
# 4. Toggle OpenCode config to force reconnection
#
# Usage: bash scripts/connect-burp.sh
# ═══════════════════════════════════════════════════════════════════════════════

DST="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$HOME/.config/opencode/opencode.json"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }

WIN_IP=$(ip route | grep default | awk '{print $3}')
WIN_PROXY_PORT=9872
PROXY_SRC="$DST/scripts/burp_proxy.py"

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

# ── Step 1: Kill stale bridge processes ──────────────────────────────────────
info "Cleaning up stale bridge processes..."
STALE_PIDS=$(pgrep -f "burp-mcp-bridge" 2>/dev/null || true)
if [ -n "$STALE_PIDS" ]; then
  kill "$STALE_PIDS" 2>/dev/null || true
  ok "Killed stale bridge: PID $STALE_PIDS"
fi

WSTG_PIDS=$(pgrep -f "uv run server.py" 2>/dev/null || true)
if [ -n "$WSTG_PIDS" ]; then
  kill $WSTG_PIDS 2>/dev/null || true
  info "Stopped existing WSTG server — will restart"
fi

# ── Step 2: Check Burp MCP on Windows ────────────────────────────────────────
info "Checking Burp MCP on Windows (port 9876)..."
BURP_PID=""
if [ -x "/mnt/c/Windows/System32/netstat.exe" ]; then
  NETSTAT_OUT=$(/mnt/c/Windows/System32/netstat.exe -ano 2>/dev/null | grep ":9876" | grep LISTENING || true)
  BURP_PID=$(echo "$NETSTAT_OUT" | awk '{print $NF}' | tr -d '\r' | head -1 || true)
fi

if [ -z "$BURP_PID" ]; then
  err "Nothing listening on port 9876"
  echo ""
  echo "  To fix:"
  echo "    1. Start Burp Suite on Windows"
  echo "    2. Extensions → MCP Server → Enable"
  echo ""
  exit 1
fi
ok "Burp MCP running (PID $BURP_PID)"

# ── Step 3: Deploy and start Windows Python proxy ────────────────────────────
info "Setting up Python proxy on Windows..."

# Auto-detect Windows paths (no hardcoded usernames)
WIN_HOME_RAW=$(cmd.exe /c "echo %USERPROFILE%" 2>/dev/null | tr -d '\r\n')
WIN_HOME_WSL=$(echo "$WIN_HOME_RAW" | sed 's|C:|/mnt/c|' | sed 's|\\|/|g')
PYTHON_WIN_RAW=$(cmd.exe /c "where python 2>nul" 2>/dev/null | tr -d '\r\n' | head -1)
if [ -z "$PYTHON_WIN_RAW" ]; then
  PYTHON_WIN_RAW="$WIN_HOME_RAW\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe"
fi
PROXY_DST_RAW="$WIN_HOME_RAW\\burp_proxy.py"
PROXY_DST_WSL="$WIN_HOME_WSL/burp_proxy.py"

# Copy proxy script to Windows
cp "$PROXY_SRC" "$PROXY_DST_WSL"
# shellcheck disable=SC2059
printf "${G}[✓]${N} Proxy script copied to %s\n" "$PROXY_DST_RAW"

# Check if proxy already running
PROXY_PID=""
if [ -x "/mnt/c/Windows/System32/netstat.exe" ]; then
  NETSTAT_OUT=$(/mnt/c/Windows/System32/netstat.exe -ano 2>/dev/null | grep ":$WIN_PROXY_PORT" | grep LISTENING || true)
  PROXY_PID=$(echo "$NETSTAT_OUT" | awk '{print $NF}' | tr -d '\r' | head -1 || true)
fi

if [ -n "$PROXY_PID" ]; then
  ok "Python proxy already running (PID $PROXY_PID)"
else
  info "Starting Python proxy on Windows..."
  cmd.exe /c "start /b \"\" \"$PYTHON_WIN_RAW\" \"$PROXY_DST_RAW\"" 2>/dev/null
  sleep 3
  if [ -x "/mnt/c/Windows/System32/netstat.exe" ]; then
    NETSTAT_OUT=$(/mnt/c/Windows/System32/netstat.exe -ano 2>/dev/null | grep ":$WIN_PROXY_PORT" | grep LISTENING || true)
    PROXY_PID=$(echo "$NETSTAT_OUT" | awk '{print $NF}' | tr -d '\r' | head -1 || true)
  fi
  if [ -n "$PROXY_PID" ]; then
    ok "Python proxy started (PID $PROXY_PID)"
  else
    err "Failed to start Python proxy"
    exit 1
  fi
fi

# ── Step 4: Verify proxy chain ────────────────────────────────────────────────
info "Verifying Burp MCP through proxy ($WIN_IP:$WIN_PROXY_PORT)..."
VERIFY_RESULT=$(timeout 10 bash <<VERIFY 2>&1
curl -s -N -H "Accept: text/event-stream" http://$WIN_IP:$WIN_PROXY_PORT/ > /tmp/burp_sse_test.txt 2>&1 &
SP=\$!
sleep 2
SID=\$(grep -oP 'sessionId=\K[^\r\n]+' /tmp/burp_sse_test.txt 2>/dev/null | head -1 | tr -d '\r\n')
if [ -z "\$SID" ]; then echo "NO_SESSION"; exit; fi
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  "http://$WIN_IP:$WIN_PROXY_PORT/?sessionId=\$SID" > /dev/null 2>&1
sleep 2
kill \$SP 2>/dev/null
grep -q "send_http1_request" /tmp/burp_sse_test.txt 2>/dev/null && echo "OK" || echo "FAIL"
VERIFY
)
echo "  Result: $VERIFY_RESULT"
if [ "$VERIFY_RESULT" = "OK" ]; then
  ok "Burp MCP proxy verified — tools/list returned successfully"
else
  warn "Proxy verification failed — re-run the script"
fi
rm -f /tmp/burp_sse_test.txt

# ── Step 5: Toggle OpenCode config ────────────────────────────────────────────
info "Toggling Burp MCP in OpenCode config..."
python3 << PYEOF
import json, os

cp = os.path.expanduser("~/.config/opencode/opencode.json")
with open(cp) as f:
    cfg = json.load(f)

burp = cfg.get("mcp", {}).get("burp")
if burp:
    del cfg["mcp"]["burp"]
    with open(cp, "w") as f:
        json.dump(cfg, f, indent=2)
    cfg["mcp"]["burp"] = burp
    with open(cp, "w") as f:
        json.dump(cfg, f, indent=2)
    print("[+] Burp MCP entry toggled — restart OpenCode")
else:
    print("[-] No burp entry in MCP config")
PYEOF

# ── Step 6: Restart WSTG server ──────────────────────────────────────────────
info "Starting Dristi WSTG MCP server (background)..."
nohup bash -c "cd '$DST/server' && exec uv run server.py" \
  > "$HOME/.dristi/server.log" 2>&1 &
sleep 2
if kill -0 $! 2>/dev/null; then
  ok "WSTG server started (PID $!)"
else
  warn "WSTG server failed — check: cat ~/.dristi/server.log"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${G}╔══════════════════════════════════════╗${N}"
echo -e "${BOLD}${G}║     Connection Complete                 ║${N}"
echo -e "${BOLD}${G}╚══════════════════════════════════════╝${N}"
echo ""
echo "  Chain: OpenCode → burp-mcp-bridge → $WIN_IP:$WIN_PROXY_PORT → Burp MCP"
echo "  Restart OpenCode for changes to take effect."
echo ""
