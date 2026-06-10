#!/bin/bash
# nuclei.sh — Run nuclei by vulnerability category against target URLs
# Usage: ./nuclei.sh <engagement-id> <class> [urls-file]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENGAGEMENT="${1:?Usage: $0 <engagement-id> <class> [urls-file]}"
CLASS="${2:?}"
URLS_FILE="${3:-$BASE_DIR/engagements/$ENGAGEMENT/recon/urls/$CLASS.txt}"
OUT_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/nuclei"
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/$CLASS.txt"

NUCLEI_DIR="/home/pwn/nuclei-templates"

# Map our class names to nuclei template paths
declare -A TEMPLATE_MAP
TEMPLATE_MAP[sqli]="dast/vulnerabilities/sqli"
TEMPLATE_MAP[xss]="dast/vulnerabilities/xss"
TEMPLATE_MAP[cmdi]="dast/vulnerabilities/cmdi"
TEMPLATE_MAP[ssti]="dast/vulnerabilities/ssti"
TEMPLATE_MAP[ssrf]="dast/vulnerabilities/ssrf"
TEMPLATE_MAP[lfi]="dast/vulnerabilities/lfi"
TEMPLATE_MAP[redirect]="dast/vulnerabilities/redirect"
TEMPLATE_MAP[xxe]="dast/vulnerabilities/xxe"
TEMPLATE_MAP[crlf]="dast/vulnerabilities/crlf"
TEMPLATE_MAP[csti]="dast/vulnerabilities/csti"
TEMPLATE_MAP[rfi]="dast/vulnerabilities/rfi"
TEMPLATE_MAP[injection]="dast/vulnerabilities/injection"

TEMPLATE_PATH="${TEMPLATE_MAP[$CLASS]:-}"
if [ -z "$TEMPLATE_PATH" ]; then
  TEMPLATE_PATH="http/vulnerabilities/other"
fi

FULL_PATH="$NUCLEI_DIR/$TEMPLATE_PATH"
if [ ! -d "$FULL_PATH" ]; then
  echo "[!] No nuclei templates for $CLASS at $FULL_PATH"
  # Fallback: try http/vulnerabilities/generic
  FULL_PATH="$NUCLEI_DIR/http/vulnerabilities/generic"
  [ ! -d "$FULL_PATH" ] && echo "[-] No fallback templates either, skipping nuclei for $CLASS" && exit 0
fi

[ ! -f "$URLS_FILE" ] && echo "[-] No URLs file: $URLS_FILE" && exit 0
URL_COUNT=$(wc -l < "$URLS_FILE")
[ "$URL_COUNT" -eq 0 ] && echo "[-] Empty URL list for $CLASS" && exit 0

echo "[+] Running nuclei $CLASS templates against $URL_COUNT URLs"
echo "    Templates: $FULL_PATH"
echo "    Output: $OUT_FILE"

nuclei -t "$FULL_PATH" -l "$URLS_FILE" -o "$OUT_FILE" -silent 2>/dev/null

if [ -f "$OUT_FILE" ]; then
  FINDINGS=$(wc -l < "$OUT_FILE")
  echo "[+] nuclei $CLASS: $FINDINGS findings"
else
  echo "[+] nuclei $CLASS: no findings"
fi
