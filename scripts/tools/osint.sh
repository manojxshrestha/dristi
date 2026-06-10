#!/bin/bash
# =============================================================================
# OSINT — Passive intelligence gathering via reconFTW modules
#
# Modules (no API keys required):
#   domain_info           — WHOIS lookup, M365/Azure tenant discovery, Scopify scope analysis
#   third_party_misconfigs — misconfig-mapper scans for exposed SaaS (Slack, Jira, GitHub, etc.)
#   spoof                 — SPF/DMARC spoofability analysis via Spoofy
#   cloud_enum_scan       — Cloud storage bucket enumeration (AWS S3, Azure Blob, GCP, DO Spaces)
#
# Skipped: ip_info (requires WHOISXML_API key)
#
# Usage:
#   ./tools/osint.sh <domain> [output_dir]
#   ./tools/osint.sh --install            # Install missing reconftw tools
#
# Output (in output_dir/osint/):
#   domain_info_general.txt       — WHOIS + msftrecon output
#   azure_tenant_domains.txt      — Microsoft/Azure-related findings
#   scopify.txt                   — Scopify scope analysis
#   3rdparts_misconfigurations.txt — Misconfigured third-party services
#   spoof.txt                     — SPF/DMARC spoofability report
#   cloud_enum.txt                — Discovered cloud storage buckets
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$HOME/.local/bin"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Install dependencies ─────────────────────────────────────────────
install_repo() {
    local repo="$1"
    local github_path="$2"
    local target_dir="$TOOLS_DIR/$repo"

    if [ -d "$target_dir/.git" ]; then
        log_info "$repo already installed at $target_dir"
        return 0
    fi

    log_info "Cloning $repo..."
    mkdir -p "$TOOLS_DIR"
    git clone --filter="blob:none" "https://github.com/$github_path" "$target_dir" 2>/dev/null || {
        log_warn "Failed to clone $repo"
        return 1
    }

    if [ -f "$target_dir/requirements.txt" ]; then
        log_info "Setting up Python venv for $repo..."
        (
            cd "$target_dir" || return 1
            uv venv venv &>/dev/null
            uv pip install --upgrade -r requirements.txt --python venv/bin/python3 &>/dev/null
        ) && log_ok "$repo venv ready" || log_warn "$repo venv setup failed"
    fi

    log_ok "$repo installed"
}

do_install() {
    log_step "Installing reconftw OSINT tools"

    if ! command -v git &>/dev/null; then log_err "git required"; return 1; fi
    if ! command -v uv &>/dev/null; then log_err "uv required (curl -LsSf https://astral.sh/uv/install.sh)"; return 1; fi

    install_repo "msftrecon" "Arcanum-Sec/msftrecon"
    install_repo "Scopify" "Arcanum-Sec/Scopify"
    install_repo "Spoofy" "MattKeeley/Spoofy"
    install_repo "cloud_enum" "initstring/cloud_enum"

    echo ""
    log_ok "Install complete"
    log_info "Installed: msftrecon, Scopify, Spoofy, cloud_enum"
    echo ""
    return 0
}

# ── Handle --install flag ────────────────────────────────────────────
if [ "${1:-}" = "--install" ]; then
    do_install
    exit $?
fi

# ── Argument parsing ────────────────────────────────────────────────
TARGET="${1:?Usage: $0 <domain> [output_dir]  or  $0 --install}"
OUT_DIR="${2:-$BASE_DIR/recon/$TARGET}"
OSINT_DIR="$OUT_DIR/osint"
mkdir -p "$OSINT_DIR"

log_info "Target: $TARGET"
log_info "Output: $OSINT_DIR"

# ── Helper: tool check ───────────────────────────────────────────────
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_warn "$1 not found — skipping"
        return 1
    fi
    return 0
}

check_repo_tool() {
    local repo="$1"
    local script_path="$TOOLS_DIR/$repo/$2"
    if [ -f "$script_path" ] || [ -f "$TOOLS_DIR/$repo/venv/bin/python3" ]; then
        return 0
    fi
    log_warn "$repo not found at $TOOLS_DIR/$repo — skipping"
    log_info "  Install: $0 --install  (or cd reconftw && ./install.sh)"
    return 1
}

# ── 1. domain_info — WHOIS + M365/Azure + Scopify ────────────────────
run_domain_info() {
    log_step "domain_info — WHOIS, M365/Azure tenant, Scopify"

    check_tool whois || return 0
    whois "$TARGET" > "$OSINT_DIR/domain_info_general.txt" 2>/dev/null && \
        log_ok "WHOIS data saved" || log_warn "WHOIS lookup failed"

    : > "$OSINT_DIR/azure_tenant_domains.txt"

    if check_repo_tool "msftrecon" "msftrecon/msftrecon.py"; then
        if command -v python3 &>/dev/null; then
            log_info "Running msftrecon..."
            local msftrecon_out
            msftrecon_out=$(mktemp)
            if python3 "$TOOLS_DIR/msftrecon/msftrecon/msftrecon.py" -d "$TARGET" > "$msftrecon_out" 2>/dev/null; then
                if [ -s "$msftrecon_out" ]; then
                    cat "$msftrecon_out" >> "$OSINT_DIR/domain_info_general.txt"
                    grep -iE 'microsoft|azure|tenant' "$msftrecon_out" > "$OSINT_DIR/azure_tenant_domains.txt" 2>/dev/null || true
                    log_ok "M365/Azure tenant info saved"
                fi
            else
                log_warn "msftrecon failed"
            fi
            rm -f "$msftrecon_out"
        fi
    fi

    if check_repo_tool "Scopify" "scopify.py"; then
        if command -v python3 &>/dev/null && command -v unfurl &>/dev/null; then
            log_info "Running Scopify..."
            local company_name
            company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')
            python3 "$TOOLS_DIR/Scopify/scopify.py" -c "$company_name" > "$OSINT_DIR/scopify.txt" 2>/dev/null && \
                log_ok "Scopify scope analysis saved" || log_warn "Scopify failed"
        else
            log_warn "unfurl or python3 missing — skipping Scopify"
        fi
    fi
}

# ── 2. third_party_misconfigs — misconfig-mapper ─────────────────────
run_third_party_misconfigs() {
    log_step "third_party_misconfigs — SaaS misconfiguration scan"

    check_tool misconfig-mapper || return 0

    local misconfig_dir
    misconfig_dir="$(command -v misconfig-mapper 2>/dev/null | xargs dirname 2>/dev/null)/misconfig-mapper"

    if [ -d "$misconfig_dir" ]; then
        log_info "Updating misconfig-mapper templates..."
        timeout 90 misconfig-mapper -update-templates &>/dev/null || true
    fi

    local company_name
    company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')

    log_info "Scanning by domain: $TARGET"
    timeout 120 misconfig-mapper -target "$TARGET" -as-domain true -permutations false -skip-ssl \
        -service "*" -verbose 0 2>/dev/null | anew -q "$OSINT_DIR/3rdparts_misconfigurations.txt" || true

    log_info "Scanning by company: $company_name"
    timeout 120 misconfig-mapper -target "$company_name" -skip-ssl -verbose 0 -service "*" \
        2>/dev/null | anew -q "$OSINT_DIR/3rdparts_misconfigurations.txt" || true

    if [ -s "$OSINT_DIR/3rdparts_misconfigurations.txt" ]; then
        log_ok "$(wc -l < "$OSINT_DIR/3rdparts_misconfigurations.txt") misconfigurations found"
    else
        log_info "No third-party misconfigurations found"
    fi
}

# ── 3. spoof — SPF/DMARC spoofability ────────────────────────────────
run_spoof() {
    log_step "spoof — SPF/DMARC spoofability check"

    check_repo_tool "Spoofy" "spoofy.py" || return 0

    local spoofy_venv="$TOOLS_DIR/Spoofy/venv/bin/python3"
    local spoofy_script="$TOOLS_DIR/Spoofy/spoofy.py"

    if [ -x "$spoofy_venv" ] && [ -f "$spoofy_script" ]; then
        log_info "Checking spoofability..."
        (cd "$TOOLS_DIR/Spoofy" && "$spoofy_venv" "$spoofy_script" -d "$TARGET") > "$OSINT_DIR/spoof.txt" 2>/dev/null
        if [ -s "$OSINT_DIR/spoof.txt" ]; then
            log_ok "Spoof report saved"
        else
            log_warn "Spoofy returned no results"
        fi
    fi
}

# ── 4. cloud_enum_scan — Cloud storage bucket enumeration ────────────
run_cloud_enum() {
    log_step "cloud_enum_scan — Cloud storage bucket enumeration"

    check_repo_tool "cloud_enum" "cloud_enum.py" || return 0

    local cloud_enum_venv="$TOOLS_DIR/cloud_enum/venv/bin/python3"
    local cloud_enum_script="$TOOLS_DIR/cloud_enum/cloud_enum.py"

    if [ -x "$cloud_enum_venv" ] && [ -f "$cloud_enum_script" ]; then
        local company_name
        company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')

        log_info "Checking: $company_name, $TARGET, ${TARGET%%.*}"

        local fuzz_file="$TOOLS_DIR/cloud_enum/enum_tools/fuzz.txt"
        local mutations="$fuzz_file"
        local brute="$fuzz_file"
        if [ ! -f "$fuzz_file" ]; then
            mutations="$cloud_enum_script"
            brute="$cloud_enum_script"
        fi

        env PYTHONWARNINGS=ignore "$cloud_enum_venv" "$cloud_enum_script" \
            -k "$company_name" \
            -k "$TARGET" \
            -k "${TARGET%%.*}" \
            -t 20 \
            -m "$mutations" \
            -b "$brute" \
            -qs 2>/dev/null | anew -q "$OSINT_DIR/cloud_enum.txt"

        if [ -s "$OSINT_DIR/cloud_enum.txt" ]; then
            log_ok "$(wc -l < "$OSINT_DIR/cloud_enum.txt") cloud resources found"
        else
            log_info "No cloud resources found"
        fi
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
log_info "Starting OSINT for $TARGET"
log_info "Modules: domain_info, third_party_misconfigs, spoof, cloud_enum_scan"
log_warn "Skipped: ip_info (requires WHOISXML_API key)"

run_domain_info
run_third_party_misconfigs
run_spoof
run_cloud_enum

echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
log_ok "OSINT complete — results in $OSINT_DIR"
for f in "$OSINT_DIR"/*; do
    [ -f "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f") lines"
done
echo -e "${GREEN}════════════════════════════════════════════${NC}"
