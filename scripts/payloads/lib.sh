# lib.sh — shared functions for payload test scripts
# Source this from test.sh files:  source "$(dirname "$0")/lib.sh"

url_encode() {
  python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null
}

inject_payload() {
  local url="$1" payload="$2"
  local encoded; encoded=$(url_encode "$payload")
  # Replace last param value, or append if no params
  if echo "$url" | grep -q '?'; then
    echo "$url" | sed "s/=[^&[:space:]]*$/=$encoded/"
  else
    echo "${url}?q=$encoded"
  fi
}

fetch_url() {
  local url="$1" tmpfile="$2"
  curl -s -S -o "$tmpfile" -w "%{http_code} %{time_total} %{size_download}" \
    --max-time 10 -L "$url" 2>/dev/null || echo "000 0 0"
}

pat_ref() {
  local class="$1" pat_dir target
  pat_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/knowledge/payloads"
  declare -A MAP=(
    [sqli]="SQL Injection"
    [xss]="XSS Injection"
    [ssrf]="Server Side Request Forgery"
    [ssti]="Server Side Template Injection"
    [cmdi]="Command Injection"
    [lfi]="File Inclusion"
    [crlf]="CRLF Injection"
    [http-param-pollution]="HTTP Parameter Pollution"
    [nosqli]="NoSQL Injection"
    [xxe]="XXE Injection"
    [cors]="CORS Misconfiguration"
    [redirect]="Open Redirect"
    [idor]="Insecure Direct Object References"
    [rce]="Command Injection"
    [jwt-confusion]="JSON Web Token"
    [cache-poison]="Web Cache Deception"
    [deserialization]="Insecure Deserialization"
    [file-upload]="Upload Insecure Files"
    [race-condition]="Race Condition"
    [http-smuggling]="Request Smuggling"
    [oauth]="OAuth Misconfiguration"
    [ldap]="LDAP Injection"
    [open-redirect]="Open Redirect"
    [csrf]="Cross-Site Request Forgery"
    [business-logic]="Business Logic Errors"
    [ato]="Account Takeover"
    [source-leak]="Insecure Source Code Management"
    [dom]="DOM Clobbering"
    [clickjacking]="Clickjacking"
    [prototype-pollution]="Prototype Pollution"
    [dependency-confusion]="Dependency Confusion"
    [mass-assignment]="Mass Assignment"
  )
  target="${MAP[$class]:-$class}"
  [ -d "$pat_dir/$target" ] && info "Reference: $target/README.md ($(wc -l < "$pat_dir/$target/README.md" 2>/dev/null || echo 0) lines)" || true
}

log()  { echo -e "\033[0;32m[+]\033[0m $1"; }
warn() { echo -e "\033[1;33m[!]\033[0m $1"; }
info() { echo -e "\033[0;36m[*]\033[0m $1"; }
err()  { echo -e "\033[0;31m[-]\033[0m $1" >&2; }
