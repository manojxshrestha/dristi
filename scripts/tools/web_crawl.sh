#!/bin/bash
# =============================================================================
# Web Crawling — hakrawler + katana + waymore + gau
#
# Takes live HTTPS URLs and runs multiple crawlers to discover endpoints,
# then merges all results into a clean deduplicated list.
#
# Usage:
#   ./tools/web_crawl.sh <domain>                    # auto paths under recon/<domain>/
#   ./tools/web_crawl.sh <domain> <live-file>        # custom live URL file
#   ./tools/web_crawl.sh <live-file>                 # direct file path, domain from path
#   ./tools/web_crawl.sh -l <live-file>              # -l flag (convenience)
#
# Examples:
#   ./tools/web_crawl.sh example.com
#   ./tools/web_crawl.sh example.com /path/to/https-subs.txt
#   ./tools/web_crawl.sh /home/pwn/dristi/recon/example.com/live_hosts.txt
#   ./tools/web_crawl.sh -l /path/to/live_urls.txt
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

TARGET_RAW="${1:?Usage: $0 <domain> [<live-file>]}"

if [[ "$TARGET_RAW" == -* ]]; then
  TARGET_RAW="${2:?Usage: $0 <domain> [<live-file>]}"
  HTTPS_SUBS="${3:-}"
else
  HTTPS_SUBS="${2:-}"
  [[ "$HTTPS_SUBS" == -* ]] && HTTPS_SUBS="${3:-}"
fi

if [[ "$TARGET_RAW" == */* ]]; then
  HTTPS_SUBS="$TARGET_RAW"
  TARGET=$(echo "$TARGET_RAW" | sed -n 's|.*/recon/\([^/]*\)/.*|\1|p')
  [ -z "$TARGET" ] && TARGET="target"
else
  TARGET="$TARGET_RAW"
  [ -z "$HTTPS_SUBS" ] && HTTPS_SUBS="$BASE_DIR/recon/$TARGET/subdomains/live_urls.txt"
fi

OUT_DIR="$BASE_DIR/recon/$TARGET/crawl"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

if [ ! -f "$HTTPS_SUBS" ] || [ ! -s "$HTTPS_SUBS" ]; then
  log_err "https-subs file not found or empty: $HTTPS_SUBS"
  log_info "Run subdomain_enum.sh first or provide --https-subs <file>"
  exit 1
fi

cp "$HTTPS_SUBS" "$OUT_DIR/https-subs.txt"
NTOTAL=$(wc -l < "$OUT_DIR/https-subs.txt" | tr -d ' ')
log_info "Loaded $NTOTAL live HTTPS URLs from $HTTPS_SUBS"

# ── Extract alive-domains.txt ───────────────────────────────────────
log_info "Extracting alive domains ..."
awk -F/ '{print $3}' "$OUT_DIR/https-subs.txt" | sort -u > "$OUT_DIR/alive-domains.txt"
NDOMS=$(wc -l < "$OUT_DIR/alive-domains.txt" | tr -d ' ')
log_ok "alive-domains.txt: $NDOMS unique domains"

# ── Ensure tools ────────────────────────────────────────────────────
for tool in hakrawler katana gau; do
  if ! command -v "$tool" &>/dev/null; then
    log_info "Installing $tool ..."
    case "$tool" in
      hakrawler) go install github.com/hakluke/hakrawler@latest 2>/dev/null ;;
      katana)    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null ;;
      gau)       go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null ;;
    esac
    log_ok "$tool installed"
  fi
done

# ── Hakrawler ───────────────────────────────────────────────────────
log_info "Running hakrawler ..."
cat "$OUT_DIR/https-subs.txt" | hakrawler -subs -u -d 3 \
  | sort -u > "$OUT_DIR/hakcrawlurls.txt" 2>/dev/null
NHAK=$(wc -l < "$OUT_DIR/hakcrawlurls.txt" | tr -d ' ')
log_ok "hakrawler: $NHAK URLs"

# ── Katana ──────────────────────────────────────────────────────────
log_info "Running katana ..."
cat "$OUT_DIR/https-subs.txt" | katana -d 3 -jc -timeout 15 -c 20 -silent \
  2>/dev/null | anew "$OUT_DIR/cleansubskatanaurls.txt" > /dev/null
NKAT=$(wc -l < "$OUT_DIR/cleansubskatanaurls.txt" | tr -d ' ')
log_ok "katana: $NKAT URLs"

# ── Setup waymore venv ──────────────────────────────────────────────
WAYMORE_DIR="$BASE_DIR/tools/waymore"
WAYMORE_BIN=""
if [ -f "$WAYMORE_DIR/venv/bin/waymore" ]; then
  WAYMORE_BIN="$WAYMORE_DIR/venv/bin/waymore"
elif command -v waymore &>/dev/null; then
  WAYMORE_BIN="waymore"
else
  log_info "Installing waymore in virtual environment ..."
  mkdir -p "$WAYMORE_DIR"
  python3 -m venv "$WAYMORE_DIR/venv"
  "$WAYMORE_DIR/venv/bin/pip" install waymore -q 2>/dev/null
  WAYMORE_BIN="$WAYMORE_DIR/venv/bin/waymore"
  log_ok "waymore installed"
fi

# ── Waymore ─────────────────────────────────────────────────────────
log_info "Running waymore ..."
$WAYMORE_BIN -i "$TARGET" -mode U -oU "$OUT_DIR/wayurls.txt" 2>/dev/null
NWAY=$(wc -l < "$OUT_DIR/wayurls.txt" 2>/dev/null | tr -d ' ')
log_ok "waymore: $NWAY URLs"

# ── Gau ─────────────────────────────────────────────────────────────
log_info "Running gau ..."
echo "$TARGET" | gau --threads 10 --subs 2>/dev/null \
  | anew "$OUT_DIR/gauurls.txt" > /dev/null
NGAU=$(wc -l < "$OUT_DIR/gauurls.txt" | tr -d ' ')
log_ok "gau: $NGAU URLs"

# ── Merge historical ────────────────────────────────────────────────
log_info "Merging historical URLs (waymore + gau) ..."
if [ -f "$OUT_DIR/wayurls.txt" ] && [ -f "$OUT_DIR/gauurls.txt" ]; then
  cat "$OUT_DIR/wayurls.txt" "$OUT_DIR/gauurls.txt" \
    | uro 2>/dev/null | sort -u > "$OUT_DIR/waygauurls.txt"
  NHIST=$(wc -l < "$OUT_DIR/waygauurls.txt" | tr -d ' ')
  log_ok "waygauurls.txt: $NHIST historical URLs"
else
  log_warn "Skipping historical merge — waymore or gau output missing"
fi

# ── Merge all crawlers ──────────────────────────────────────────────
log_info "Merging all crawled results ..."
cat "$OUT_DIR/waygauurls.txt" \
    "$OUT_DIR/cleansubskatanaurls.txt" \
    "$OUT_DIR/hakcrawlurls.txt" \
  | uro 2>/dev/null | sort -u > "$OUT_DIR/merged-crawl.txt"
NMERGED=$(wc -l < "$OUT_DIR/merged-crawl.txt" | tr -d ' ')
log_ok "merged-crawl.txt: $NMERGED unique URLs"

# ── Filter.sh ───────────────────────────────────────────────────────
FILTER_SH="$BASE_DIR/tools/filter.sh"
if [ ! -f "$FILTER_SH" ]; then
  log_info "Downloading filter.sh ..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/scripts/refs/heads/main/filter.sh" -O "$FILTER_SH"
  chmod +x "$FILTER_SH"
fi

log_info "Filtering live URLs from merged-crawl.txt ..."
cd "$OUT_DIR" && echo "$TARGET" | bash "$FILTER_SH" 2>/dev/null
cd "$BASE_DIR"

if [ -f "$OUT_DIR/crawledurls.txt" ]; then
  NCRAWL=$(wc -l < "$OUT_DIR/crawledurls.txt" | tr -d ' ')
  log_ok "crawledurls.txt: $NCRAWL live URLs (final)"
else
  log_warn "filter.sh failed — using merged-crawl.txt as crawledurls.txt"
  cp "$OUT_DIR/merged-crawl.txt" "$OUT_DIR/crawledurls.txt"
fi

log_ok "Done. All outputs in $OUT_DIR/"
