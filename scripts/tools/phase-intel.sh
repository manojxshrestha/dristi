#!/bin/bash
# =============================================================================
# Intel — Passive intelligence gathering
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
#   ./tools/phase-intel.sh <domain> [output_dir]
#   ./tools/phase-intel.sh --install            # Install missing tools
#
# Output (in output_dir/intel/):
#   domain_info_general.txt       — WHOIS + msftrecon output
#   azure_tenant_domains.txt      — Microsoft/Azure-related findings
#   scopify.txt                   — Scopify scope analysis
#   3rdparts_misconfigurations.txt — Misconfigured third-party services
#   spoof.txt                     — SPF/DMARC spoofability report
#   cloud_enum.txt                — Discovered cloud storage buckets
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS_DIR="$HOME/.local/bin"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

export PATH="$HOME/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

# ── Default output: engagements/recon/<domain>/ ─────

# ── Global timeout: 20 minutes per module ────────────────────────────
MODULE_TIMEOUT=${MODULE_TIMEOUT:-1200}

# ── Run a command with timeout ────────────────────────────────────────
_run_with_timeout() {
    local logfile="$1"
    shift
    timeout "$MODULE_TIMEOUT" bash -c "$* >> '$logfile' 2>&1"
    local rc=$?
    if [ $rc -eq 124 ]; then
        log_warn "Timed out after ${MODULE_TIMEOUT}s"
        return 124
    fi
    return $rc
}

# ── Install dependencies ─────────────────────────────────────────────
_setup_venv() {
    local target_dir="$1"
    local req_file="$2"

    # Recreate venv if broken (missing pip or no venv at all)
    if [ ! -d "$target_dir/venv" ] || [ ! -f "$target_dir/venv/bin/python3" ] || ! "$target_dir/venv/bin/python3" -m pip --version &>/dev/null 2>&1; then
        log_info "Creating/recreating venv for $(basename "$target_dir")..."
        rm -rf "$target_dir/venv"
        uv venv "$target_dir/venv" &>/dev/null || return 1
    fi

    if [ -n "$req_file" ] && [ -f "$req_file" ]; then
        uv pip install --python "$target_dir/venv/bin/python" -r "$req_file" &>/dev/null || return 1
    elif [ -f "$target_dir/pyproject.toml" ]; then
        # Install deps from pyproject.toml (no requirements.txt)
        uv pip install --python "$target_dir/venv/bin/python" \
            dnspython requests requests-futures &>/dev/null || return 1
    fi

    return 0
}

install_repo() {
    local repo="$1"
    local github_path="$2"
    local target_dir="$TOOLS_DIR/$repo"

    if [ -d "$target_dir/.git" ]; then
        log_info "$repo already installed at $target_dir"
        # Ensure venv is healthy even if repo exists
        if [ -d "$target_dir/venv" ]; then
            if ! "$target_dir/venv/bin/python3" -m pip --version &>/dev/null 2>&1; then
                log_info "Recreating broken venv for $repo..."
                _setup_venv "$target_dir" "$target_dir/requirements.txt" \
                    && log_ok "$repo venv recreated" \
                    || log_warn "$repo venv recreation failed"
            fi
        else
            log_info "Creating venv for $repo..."
            _setup_venv "$target_dir" "$target_dir/requirements.txt" \
                && log_ok "$repo venv ready" \
                || log_warn "$repo venv setup failed"
        fi
        return 0
    fi

    log_info "Cloning $repo..."
    mkdir -p "$TOOLS_DIR"
    git clone --filter="blob:none" "https://github.com/$github_path" "$target_dir" 2>/dev/null || {
        log_warn "Failed to clone $repo"
        return 1
    }

    if [ -f "$target_dir/requirements.txt" ] || [ -f "$target_dir/pyproject.toml" ]; then
        log_info "Setting up Python venv for $repo..."
        _setup_venv "$target_dir" "$target_dir/requirements.txt" \
            && log_ok "$repo venv ready" \
            || log_warn "$repo venv setup failed"
    fi

    log_ok "$repo installed"
}

do_install() {
    log_step "Installing Intel tools"

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
OUT_DIR="${2:-${RECON_BASE}/$TARGET}"
INTEL_DIR="$OUT_DIR/intel"
mkdir -p "$INTEL_DIR"

log_info "Target: $TARGET"
log_info "Output: $INTEL_DIR"

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
    log_info "  Install: $0 --install"
    return 1
}

# ── 1. domain_info — WHOIS + M365/Azure + Scopify ────────────────────
run_domain_info() {
    log_step "domain_info — WHOIS, M365/Azure tenant, Scopify"

    check_tool whois || return 0
    _run_with_timeout "$INTEL_DIR/domain_info_general.txt" \
        "whois '$TARGET' 2>/dev/null" || true
    if [ -s "$INTEL_DIR/domain_info_general.txt" ]; then
        log_ok "WHOIS data saved"
    else
        log_warn "WHOIS lookup failed"
    fi

    : > "$INTEL_DIR/azure_tenant_domains.txt"

    if check_repo_tool "msftrecon" "msftrecon/msftrecon.py"; then
        local msftrecon_venv="$TOOLS_DIR/msftrecon/venv/bin/python3"
        if [ -x "$msftrecon_venv" ]; then
            local msftrecon_out
            msftrecon_out=$(mktemp)
            if _run_with_timeout "$msftrecon_out" \
                "'$msftrecon_venv' '$TOOLS_DIR/msftrecon/msftrecon/msftrecon.py' -d '$TARGET'"; then
                if [ -s "$msftrecon_out" ]; then
                    cat "$msftrecon_out" >> "$INTEL_DIR/domain_info_general.txt"
                    grep -iE 'microsoft|azure|tenant' "$msftrecon_out" > "$INTEL_DIR/azure_tenant_domains.txt" 2>/dev/null || true
                    log_ok "M365/Azure tenant info saved"
                fi
            else
                log_warn "msftrecon failed"
            fi
            rm -f "$msftrecon_out"
        else
            log_warn "msftrecon venv not found — run $0 --install"
        fi
    fi

    if check_repo_tool "Scopify" "scopify.py"; then
        local scopify_venv="$TOOLS_DIR/Scopify/venv/bin/python3"
        if [ -x "$scopify_venv" ] && command -v unfurl &>/dev/null; then
            local company_name
            company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')
            _run_with_timeout "$INTEL_DIR/scopify.txt" \
                "'$scopify_venv' '$TOOLS_DIR/Scopify/scopify.py' -c '$company_name'" \
                && log_ok "Scopify scope analysis saved" || log_warn "Scopify failed"
        else
            log_warn "unfurl or venv python missing — skipping Scopify"
        fi
    fi
}

# ── 2. third_party_misconfigs — SaaS misconfiguration scan ───────────
run_third_party_misconfigs() {
    log_step "third_party_misconfigs — SaaS misconfiguration scan"

    check_tool misconfig-mapper || return 0

    local templates_dir="$TOOLS_DIR/misconfig-mapper/templates"
    mkdir -p "$templates_dir"

    log_info "Updating misconfig-mapper templates..."
    misconfig-mapper -update-templates -templates "$templates_dir" 2>/dev/null || true

    local company_name
    company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')

    log_info "Scanning domain: $TARGET"
    timeout "$MODULE_TIMEOUT" misconfig-mapper -target "$TARGET" -as-domain true -permutations false -skip-ssl -service '*' -verbose 0 -templates "$templates_dir" 2>/dev/null \
        | anew -q "$INTEL_DIR/3rdparts_misconfigurations.txt" || true

    log_info "Scanning company: $company_name"
    timeout "$MODULE_TIMEOUT" misconfig-mapper -target "$company_name" -skip-ssl -verbose 0 -service '*' -templates "$templates_dir" 2>/dev/null \
        | anew -q "$INTEL_DIR/3rdparts_misconfigurations.txt" || true

    if [ -s "$INTEL_DIR/3rdparts_misconfigurations.txt" ]; then
        log_ok "$(wc -l < "$INTEL_DIR/3rdparts_misconfigurations.txt") misconfigurations found"
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
        _run_with_timeout "$INTEL_DIR/spoof.txt" \
            "cd '$TOOLS_DIR/Spoofy' && '$spoofy_venv' '$spoofy_script' -d '$TARGET'" || true
        if [ -s "$INTEL_DIR/spoof.txt" ]; then
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

        local fuzz_file="$TOOLS_DIR/cloud_enum/enum_tools/fuzz.txt"
        local mutations="$fuzz_file"
        local brute="$fuzz_file"
        if [ ! -f "$fuzz_file" ]; then
            mutations="$cloud_enum_script"
            brute="$cloud_enum_script"
        fi

        _run_with_timeout "$INTEL_DIR/cloud_enum.txt" \
            "env PYTHONWARNINGS=ignore '$cloud_enum_venv' '$cloud_enum_script' \
                -k '$company_name' \
                -k '$TARGET' \
                -k '${TARGET%%.*}' \
                -t 50 \
                -m '$mutations' \
                -b '$brute' \
                -qs 2>/dev/null | anew -q '$INTEL_DIR/cloud_enum.txt'" || true

        if [ -s "$INTEL_DIR/cloud_enum.txt" ]; then
            log_ok "$(wc -l < "$INTEL_DIR/cloud_enum.txt") cloud resources found"
        else
            log_info "No cloud resources found"
        fi
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
log_info "Starting intel for $TARGET"
log_info "Modules: domain_info, third_party_misconfigs, spoof, cloud_enum_scan"
log_warn "Skipped: ip_info (requires WHOISXML_API key)"

_run_module() {
    local display_name="$1"
    local func_name="$2"
    # Export all helper functions + vars for subshell
    local funcs
    funcs="$(declare -f log_ok log_err log_warn log_info log_step check_tool check_repo_tool _run_with_timeout _setup_venv install_repo do_install run_domain_info run_third_party_misconfigs run_spoof run_cloud_enum)"
    export TARGET INTEL_DIR TOOLS_DIR MODULE_TIMEOUT GREEN RED YELLOW CYAN NC HOME PATH
    timeout "$MODULE_TIMEOUT" bash -c "$funcs; $func_name" 2>&1
    local rc=$?
    if [ $rc -eq 124 ]; then
        log_warn "${display_name} timed out after ${MODULE_TIMEOUT}s"
    elif [ $rc -ne 0 ]; then
        log_err "${display_name} failed (exit $rc)"
    fi
    return $rc
}

_run_module "domain_info" run_domain_info
_run_module "third_party_misconfigs" run_third_party_misconfigs
_run_module "spoof" run_spoof
_run_module "cloud_enum_scan" run_cloud_enum

echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
log_ok "Intel complete — results in $INTEL_DIR"
for f in "$INTEL_DIR"/*; do
    [ -f "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f") lines"
done
echo -e "${GREEN}════════════════════════════════════════════${NC}"
