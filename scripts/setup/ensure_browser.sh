#!/usr/bin/env bash
set -euo pipefail

# Ensure Chromium browser is available for Playwright-based agents
# Usage: bash scripts/setup/ensure_browser.sh

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Checking Chromium availability..."

if /opt/google/chrome/chrome --version &>/dev/null; then
    echo "[✓] Chromium already installed at /opt/google/chrome/chrome"
    echo "    $($HOME/.cache/ms-playwright/chromium-*/chrome-linux64/chrome --version 2>/dev/null)"
    exit 0
fi

# Check if npx playwright is available
if ! command -v npx &>/dev/null; then
    echo "[✗] npx not found. Install Node.js first."
    exit 1
fi

echo "[*] Ensuring Playwright browsers are cached..."
mkdir -p "$HOME/.cache/ms-playwright"
npx playwright install chromium 2>&1 | tail -5

CHROMIUM_DIR=$(ls -d "$HOME/.cache/ms-playwright/chromium-"* 2>/dev/null | head -1)
if [ -z "$CHROMIUM_DIR" ]; then
    echo "[✗] Chromium download failed."
    exit 1
fi

CHROMIUM_BIN="$CHROMIUM_DIR/chrome-linux64/chrome"
if [ ! -f "$CHROMIUM_BIN" ]; then
    echo "[✗] Chromium binary not found at $CHROMIUM_BIN"
    exit 1
fi

echo "[*] Installing system dependencies (requires sudo)..."
if sudo -n true 2>/dev/null; then
    sudo apt-get install -y libglib2.0-0 libnss3 libnspr4 libcups2t64 libxkbcommon0 libasound2t64 libgbm1 libcairo2 libpango-1.0-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libatspi2.0-0 libatk-bridge2.0-0 libdrm2 libfontconfig1 2>&1 | tail -3
    echo "[✓] System dependencies installed"
else
    echo "[!] No sudo access. Run this manually:"
    echo "    sudo apt-get install -y libglib2.0-0 libnss3 libnspr4 libcups2t64 libxkbcommon0 libasound2t64 libgbm1 libcairo2 libpango-1.0-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libatspi2.0-0 libatk-bridge2.0-0 libdrm2 libfontconfig1"
fi

echo "[*] Creating symlink at /opt/google/chrome/chrome..."
sudo mkdir -p /opt/google/chrome
sudo ln -sf "$CHROMIUM_BIN" /opt/google/chrome/chrome

echo "[✓] Chromium ready: $CHROMIUM_BIN"
echo "    Version: $("$CHROMIUM_BIN" --version 2>&1)"
