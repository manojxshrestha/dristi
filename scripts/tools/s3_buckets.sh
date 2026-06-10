#!/bin/bash
# =============================================================================
# S3 / Cloud Bucket Scanner — enumerate cloud buckets from discovered subdomains
#
# Based on reconFTW's s3buckets() function. Runs:
#   1. cloud_enum — scans discovered subdomains for cloud storage buckets
#      (AWS S3, Azure Blob, GCP, DigitalOcean Spaces)
#   2. s3scanner — checks subdomain list for valid S3 buckets
#   3. trufflehog — scans public buckets for leaked secrets
#
# Usage:
#   ./tools/s3_buckets.sh <domain> [recon_dir]
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

TARGET="${1:?Usage: $0 <domain> [recon_dir]}"
RECON_DIR="${2:-$BASE_DIR/recon/$TARGET}"
SUBDOMAIN_DIR="$RECON_DIR/subdomains"
CLOUD_DIR="$RECON_DIR/clouds"
mkdir -p "$CLOUD_DIR" "$SUBDOMAIN_DIR"

log_info "Target: $TARGET"
log_info "Output: $CLOUD_DIR"

# ── 1. cloud_enum on subdomains ──────────────────────────────────────
run_cloud_enum() {
    log_step "cloud_enum — bucket enumeration from subdomains"

    local cloud_enum_venv="$TOOLS_DIR/cloud_enum/venv/bin/python3"
    local cloud_enum_script="$TOOLS_DIR/cloud_enum/cloud_enum.py"

    if [ ! -x "$cloud_enum_venv" ] || [ ! -f "$cloud_enum_script" ]; then
        log_warn "cloud_enum not installed — run ./tools/phase-intel.sh --install"
        log_info "Fallback: trying s3scanner on subdomains only"
        return 1
    fi

    local company_name
    company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')

    local fuzz_file="$TOOLS_DIR/cloud_enum/enum_tools/fuzz.txt"
    local mutations="$fuzz_file"
    local brute="$fuzz_file"
    if [ ! -f "$fuzz_file" ]; then
        mutations="$cloud_enum_script"
        brute="$cloud_enum_script"
    fi

    log_info "Running cloud_enum with keywords: $company_name, $TARGET, ${TARGET%%.*}"

    env PYTHONWARNINGS=ignore "$cloud_enum_venv" "$cloud_enum_script" \
        -k "$company_name" \
        -k "$TARGET" \
        -k "${TARGET%%.*}" \
        -t 20 \
        -m "$mutations" \
        -b "$brute" \
        -qs \
        -f json -l "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null

    local json_count=0
    if [ -f "$CLOUD_DIR/cloud_enum_results.jsonl" ]; then
        json_count=$(jq -Rr 'fromjson? | select(.target != null) | .target' "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null | sort -u | wc -l)
        # Also save readable format
        jq -Rr 'fromjson? | select(.target != null) | .target' "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null | sort -u > "$CLOUD_DIR/cloud_assets.txt"
        log_ok "$json_count cloud resources found via cloud_enum"
    fi

    # Extract public AWS buckets for trufflehog
    if [ -f "$CLOUD_DIR/cloud_enum_results.jsonl" ]; then
        jq -Rr '
            fromjson? | select(type == "object")
            | select(.platform == "aws" and .access == "public")
            | .target
        ' "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null | sort -u > "$CLOUD_DIR/public_aws_targets.txt" || true

        jq -Rr '
            fromjson? | select(type == "object")
            | select(.platform == "gcp" and .access == "public")
            | .target
        ' "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null | sort -u > "$CLOUD_DIR/public_gcp_targets.txt" || true

        [ -s "$CLOUD_DIR/public_aws_targets.txt" ] && log_info "$(wc -l < "$CLOUD_DIR/public_aws_targets.txt") public AWS targets"
        [ -s "$CLOUD_DIR/public_gcp_targets.txt" ] && log_info "$(wc -l < "$CLOUD_DIR/public_gcp_targets.txt") public GCP targets"
    fi

    return 0
}

# ── 2. s3scanner on subdomains ───────────────────────────────────────
run_s3scanner() {
    log_step "s3scanner — S3 bucket check on subdomains"

    check_tool s3scanner || return 0

    local subdomain_file="$SUBDOMAIN_DIR/all_subdomains.txt"
    if [ ! -f "$subdomain_file" ]; then
        subdomain_file="$SUBDOMAIN_DIR/subdomains.txt"
    fi
    if [ ! -f "$subdomain_file" ] || [ ! -s "$subdomain_file" ]; then
        log_warn "No subdomains found at $SUBDOMAIN_DIR — skipping s3scanner"
        return 0
    fi

    log_info "Scanning $(wc -l < "$subdomain_file") subdomains for S3 buckets..."
    s3scanner -bucket-file "$subdomain_file" 2>/dev/null | anew -q "$CLOUD_DIR/s3buckets.txt"

    if [ -s "$CLOUD_DIR/s3buckets.txt" ]; then
        local clean_count
        clean_count=$(grep -aiv "not_exist\|Warning:\|invalid_name\|^http" "$CLOUD_DIR/s3buckets.txt" 2>/dev/null | awk 'NF' | wc -l)
        log_ok "$clean_count valid S3 buckets found"
    else
        log_info "No S3 buckets found via s3scanner"
    fi
}

# ── 3. trufflehog on public buckets ───────────────────────────────────
run_trufflehog() {
    log_step "trufflehog — secret scanning on discovered buckets"

    check_tool trufflehog || return 0

    # Scan from s3scanner results
    if [ -f "$CLOUD_DIR/s3buckets.txt" ] && [ -s "$CLOUD_DIR/s3buckets.txt" ]; then
        local bucket_count=0
        while IFS= read -r bucket; do
            bucket=$(echo "$bucket" | xargs)
            [ -z "$bucket" ] && continue
            [[ "$bucket" == "not_exist"* ]] && continue
            [[ "$bucket" == "Warning:"* ]] && continue
            log_info "Scanning S3 bucket: $bucket"
            trufflehog s3 --bucket="$bucket" -j 2>/dev/null | jq -c 2>/dev/null | anew -q "$CLOUD_DIR/s3_trufflehog.txt"
            ((bucket_count++))
        done < "$CLOUD_DIR/s3buckets.txt"
        [ -s "$CLOUD_DIR/s3_trufflehog.txt" ] && log_ok "$(wc -l < "$CLOUD_DIR/s3_trufflehog.txt") secrets found in S3 buckets"
    fi

    # Scan from cloud_enum public AWS targets
    if [ -f "$CLOUD_DIR/public_aws_targets.txt" ] && [ -s "$CLOUD_DIR/public_aws_targets.txt" ]; then
        while IFS= read -r target; do
            local bucket_name=""
            local host="${target#http://}"
            host="${host#https://}"
            host="${host%%/*}"
            if [[ "$host" =~ ^([^.]+)\.s3([.-][^.]+)?\.amazonaws\.com$ ]]; then
                bucket_name="${BASH_REMATCH[1]}"
            fi
            if [ -n "$bucket_name" ]; then
                log_info "Scanning cloud_enum bucket: $bucket_name"
                trufflehog s3 --bucket="$bucket_name" -j 2>/dev/null | jq -c 2>/dev/null | anew -q "$CLOUD_DIR/cloud_enum_trufflehog.txt"
            fi
        done < "$CLOUD_DIR/public_aws_targets.txt"
        [ -s "$CLOUD_DIR/cloud_enum_trufflehog.txt" ] && log_ok "$(wc -l < "$CLOUD_DIR/cloud_enum_trufflehog.txt") secrets found in cloud_enum buckets"
    fi

    # Scan from cloud_enum public GCP targets
    if [ -f "$CLOUD_DIR/public_gcp_targets.txt" ] && [ -s "$CLOUD_DIR/public_gcp_targets.txt" ]; then
        while IFS= read -r target; do
            local target_ns="${target#http://}"
            target_ns="${target_ns#https://}"
            local gcp_bucket=""
            if [[ "$target_ns" == storage.googleapis.com/* ]]; then
                gcp_bucket="${target_ns#storage.googleapis.com/}"
                gcp_bucket="${gcp_bucket%%/*}"
            elif [[ "$target_ns" =~ ^([^.]+)\.storage\.googleapis\.com(/.*)?$ ]]; then
                gcp_bucket="${BASH_REMATCH[1]}"
            fi
            if [ -n "$gcp_bucket" ]; then
                log_info "Scanning GCP bucket: $gcp_bucket"
                trufflehog gcs --project-id="$gcp_bucket" -j 2>/dev/null | jq -c 2>/dev/null | anew -q "$CLOUD_DIR/cloud_enum_trufflehog.txt"
            fi
        done < "$CLOUD_DIR/public_gcp_targets.txt"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
run_cloud_enum
run_s3scanner
run_trufflehog

echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
log_ok "S3/cloud bucket scan complete — results in $CLOUD_DIR"
for f in "$CLOUD_DIR"/*; do
    [ -f "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f") lines"
done
echo -e "${GREEN}════════════════════════════════════════════${NC}"
