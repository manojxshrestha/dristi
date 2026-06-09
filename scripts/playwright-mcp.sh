#!/bin/bash
# Playwright MCP wrapper — auto-detects BurpSuite proxy on WSL2/Linux/macOS
#
# Auto-detects the Windows host IP (WSL2) or uses localhost for native setups,
# then passes --proxy-server to @playwright/mcp so ALL browser traffic routes
# through BurpSuite automatically — no manual steps, no monkey-patching.
#
# Behaviour:
#   WSL2           → Detects Windows host from default gateway
#   Native Linux   → Uses 127.0.0.1 (Burp on host)
#   macOS          → Uses 127.0.0.1 (Burp on host)
#   CI / Disabled  → Set PLAYWRIGHT_BURP_DISABLE=true → no proxy
#
# Bypass list (domains that skip Burp):
#   localhost, 127.0.0.1, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

set -euo pipefail

# ── Auto-detect BurpSuite host ──────────────────────────────────────────────

WIN_IP=""

if [ -n "${PLAYWRIGHT_BURP_DISABLE:-}" ]; then
  : # explicitly disabled, WIN_IP stays empty
elif command -v ip &>/dev/null && ip route 2>/dev/null | grep -q default; then
  # WSL2 / Linux: default gateway is the host
  WIN_IP=$(ip route | grep default | awk '{print $3}')
elif [ -f /proc/sys/fs/binfmt_misc/WSLInterop ] || [ -n "${WSL_DISTRO_NAME:-}" ]; then
  # WSL fallback (ip route failed)
  WIN_IP="172.17.160.1"
elif [ "$(uname)" = "Darwin" ]; then
  # macOS: Burp typically runs on localhost
  WIN_IP="127.0.0.1"
else
  # Native Linux fallback
  WIN_IP="127.0.0.1"
fi

export WIN_IP

# ── Build proxy args ────────────────────────────────────────────────────────

PROXY_ARGS=()

if [ -n "$WIN_IP" ]; then
  PROXY_SERVER="http://${WIN_IP}:8080"
  export PLAYWRIGHT_BURP_PROXY="$PROXY_SERVER"
  PROXY_ARGS+=( "--proxy-server" "$PROXY_SERVER" )
  PROXY_ARGS+=( "--proxy-bypass" "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" )
  echo "[playwright-mcp] Proxy: $PROXY_SERVER (bypass private ranges)" >&2
else
  export PLAYWRIGHT_BURP_PROXY=""
  echo "[playwright-mcp] No proxy (disabled or not detected)" >&2
fi

# ── Stealth init script (anti-fingerprinting) ───────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SCRIPT="$SCRIPT_DIR/playwright-stealth.js"
if [ -f "$INIT_SCRIPT" ]; then
  PROXY_ARGS+=( "--init-script" "$INIT_SCRIPT" )
  echo "[playwright-mcp] Stealth: $INIT_SCRIPT" >&2
fi

# Realistic User-Agent (override headless default)
PROXY_ARGS+=( "--user-agent" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" )

# ── Launch ──────────────────────────────────────────────────────────────────

exec npx -y @playwright/mcp "${PROXY_ARGS[@]}" "$@"
