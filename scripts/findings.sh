#!/usr/bin/env bash
# ── Dristi Findings Database CLI ─────────────────────────────────────────────
# Cross-session persistence via SQLite.
# Usage: ./scripts/findings.sh <command> [args...]
#
# Commands:
#   init <id> [--client "X"] [--type web] [--scope "X"]
#   add host <engagement> <ip> [--hostname X] [--os X] [--role X]
#   add service <engagement> <host_ip> <port> [--protocol tcp] [--service X]
#   add vuln <engagement> <title> --severity S [--url X] [--test X]
#   add cred <engagement> <username> <secret> [--type password]
#   add chain <engagement> <name> [--score 0] [--mitre X]
#   log <engagement> <agent> <action> <summary>
#   list hosts|vulns|services|creds|chains|log [engagement]
#   stats <engagement>
#   export <engagement>
#   handoff <engagement>
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/../server" && pwd)"
DB_PATH="${DST_FINDINGS_DB:-$SERVER_DIR/data/findings.db}"

usage() {
    sed -n 's/^# \?/  /p' "$0" | sed -n '3,/^$/p'
    exit 1
}

# ── Helper: parse key=value args into JSON ──────────────────────────────────
parse_flags() {
    local json="{}"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --client)    json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['client']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --type)      json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['etype']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --scope)     json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['scope']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --hostname)  json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['hostname']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --os)        json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['os']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --role)      json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['role']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --protocol)  json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['protocol']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --service)   json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['service']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --version)   json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['version']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --severity)  json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['severity']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --secret-type) json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['secret_type']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --access-level) json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['access_level']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --cvss)      json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['cvss']=$2; print(json.dumps(d))") ; shift 2 ;;
            --url)       json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['affected_url']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --param)     json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['affected_parameter']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --test)      json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['test_id']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --tool)      json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['tool_used']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --cve)       json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['cve']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --mitre)     json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['mitre_ids']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --discovered) json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['discovered_by']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --domain)    json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['domain']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --score)     json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['score']=$2; print(json.dumps(d))") ; shift 2 ;;
            --source)    json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['source']='$2'; print(json.dumps(d))") ; shift 2 ;;
            --notes)     json=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); d['notes']='$2'; print(json.dumps(d))") ; shift 2 ;;
            *)           shift ;;
        esac
    done
    echo "$json"
}

cmd_init() {
    local id="$1"; shift
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
eng = db.init_engagement('$id', f.get('client',''), f.get('etype','web'), f.get('scope',''), f.get('notes',''))
db.log_action('$id', 'cli', 'init', 'Engagement $id initialized', str(eng))
print(json.dumps(eng, indent=2, default=str))
"
}

cmd_add_host() {
    local eid="$1"; shift
    local ip="$1"; shift
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
h = db.add_host('$eid', '$ip', f.get('hostname',''), f.get('os',''), f.get('role',''), f.get('discovered_by',''), f.get('notes',''))
db.log_action('$eid', 'cli', 'add_host', 'Host $ip added', str(h))
print(json.dumps(h, indent=2, default=str))
"
}

cmd_add_service() {
    local eid="$1"; shift
    local host_ip="$1"; shift
    local port="$1"; shift
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
hosts = db.list_hosts('$eid')
hid = None
for h in hosts:
    if h['ip'] == '$host_ip' or h['hostname'] == '$host_ip':
        hid = h['id']
        break
if hid is None:
    print(f'Host {host_ip} not found')
    sys.exit(1)
svc = db.add_service(hid, $port, f.get('protocol','tcp'), f.get('service',''), f.get('version',''), f.get('notes',''))
print(json.dumps(svc, indent=2, default=str))
"
}

cmd_add_vuln() {
    local eid="$1"; shift
    local title="$1"; shift
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
v = db.add_vuln('$eid', '$title', f.get('severity','medium'), f.get('cvss',0.0), f.get('cve',''), f.get('mitre_ids',''), f.get('test_id',''), f.get('tool_used',''), f.get('affected_url',''), f.get('affected_parameter',''), '', '', '', f.get('domain',''))
db.log_action('$eid', 'cli', 'add_vuln', v['title'], str(v))
print(json.dumps(v, indent=2, default=str))
"
}

cmd_add_cred() {
    local eid="$1"; shift
    local username="$1"; shift
    local secret="$1"; shift
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
c = db.add_credential('$eid', '$username', '$secret', f.get('secret_type','password'), f.get('domain',''), f.get('access_level','unknown'), f.get('source',''), f.get('notes',''))
db.log_action('$eid', 'cli', 'add_cred', c['username'], str(c))
print(json.dumps(c, indent=2, default=str))
"
}

cmd_add_chain() {
    local eid="$1"; shift
    local name="$1"; shift
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
c = db.add_chain('$eid', '$name', f.get('score',0.0), [], f.get('mitre_ids',''), f.get('notes',''))
print(json.dumps(c, indent=2, default=str))
"
}

cmd_log() {
    local eid="$1"; shift
    local agent="$1"; shift
    local action="$1"; shift
    local summary="${1:-}"; shift || true
    local flags
    flags=$(parse_flags "$@")
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
f = json.loads('$flags')
e = db.log_action('$eid', '$agent', '$action', '$summary', f.get('notes',''))
print(json.dumps(e, indent=2, default=str))
"
}

cmd_list() {
    local what="$1"
    local eid="${2:-}"
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
if '$what' == 'hosts':
    data = db.list_hosts('$eid')
elif '$what' == 'vulns':
    data = db.list_vulns(engagement_id='$eid')
elif '$what' == 'services':
    data = db.list_services(engagement_id='$eid')
elif '$what' == 'creds':
    data = db.list_credentials(engagement_id='$eid')
elif '$what' == 'chains':
    data = db.list_chains(engagement_id='$eid')
elif '$what' == 'log':
    data = db.get_session_log(engagement_id='$eid')
else:
    print(f'Unknown list type: $what')
    sys.exit(1)
if not data:
    print(f'No {\"$what\"} found.')
    sys.exit(0)
print(json.dumps(data, indent=2, default=str))
"
}

cmd_stats() {
    local eid="$1"
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
s = db.stats('$eid')
if not s.get('engagement'):
    print(f'No engagement found for $eid')
    sys.exit(1)
print(json.dumps(s, indent=2, default=str))
"
}

cmd_export() {
    local eid="$1"
    python3 -c "
import sys, json
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
print(db.export_json('$eid'))
"
}

cmd_handoff() {
    local eid="$1"
    python3 -c "
import sys
sys.path.insert(0, '$SERVER_DIR')
from findings_db import get_db
db = get_db('$DB_PATH')
print(db.handoff_markdown('$eid'))
"
}

main() {
    [[ $# -lt 1 ]] && usage
    local cmd="$1"; shift

    case "$cmd" in
        init)       [[ $# -ge 1 ]] || usage; cmd_init "$@" ;;
        add)        [[ $# -ge 3 ]] || usage
                    local sub="$1"; shift
                    case "$sub" in
                        host) cmd_add_host "$@" ;;
                        service) cmd_add_service "$@" ;;
                        vuln) cmd_add_vuln "$@" ;;
                        cred) cmd_add_cred "$@" ;;
                        chain) cmd_add_chain "$@" ;;
                        *) usage ;;
                    esac ;;
        log)        [[ $# -ge 3 ]] || usage; cmd_log "$@" ;;
        list)       [[ $# -ge 1 ]] || usage; cmd_list "$@" ;;
        stats)      [[ $# -ge 1 ]] || usage; cmd_stats "$@" ;;
        export)     [[ $# -ge 1 ]] || usage; cmd_export "$@" ;;
        handoff)    [[ $# -ge 1 ]] || usage; cmd_handoff "$@" ;;
        doctor)     cmd_doctor ;;
        *)          usage ;;
    esac
}

# Doctor: audit CLI tools availability (like pentest-ai-agents' doctor.sh)
cmd_doctor() {
    echo "# Dristi Tool Doctor"
    echo ""
    echo "Checking CLI tools required for WSTG phases..."
    echo ""

    local tools=(
        "nmap:nmap:Phase 0 - Recon"
        "nuclei:nuclei:Phase 0 - Vuln Scan"
        "ffuf:ffuf:Phase 0 - Fuzzing"
        "gobuster:gobuster:Phase 0 - Directory busting"
        "feroxbuster:feroxbuster:Phase 0 - Directory busting"
        "httpx:httpx:Phase 0 - HTTP probing"
        "whatweb:whatweb:Phase 0 - Fingerprinting"
        "katana:katana:Phase 0 - Crawling"
        "gau:gau:Phase 0 - URL gathering"
        "subfinder:subfinder:Phase 0 - Subdomain enum"
        "amass:amass:Phase 0 - Subdomain enum"
        "dnsx:dnsx:Phase 0 - DNS probing"
        "sqlmap:sqlmap:Phase 4 - SQL injection"
        "dalfox:dalfox:Phase 4 - XSS scanning"
        "commix:commix:Phase 4 - Command injection"
        "hydra:hydra:Phase 3 - Brute force"
        "wafw00f:wafw00f:Phase 0 - WAF detection"
        "arjun:arjun:Phase 0 - Parameter discovery"
        "corscanner:corscanner:Phase 2 - CORS testing"
        "smuggler:smuggler:Phase 4 - Request smuggling"
        "crlfuzz:crlfuzz:Phase 4 - CRLF injection"
        "nikto:nikto:Phase 0 - Web server scan"
        "wapiti:wapiti:Phase 0 - Web vuln scan"
        "urless:urless:Phase 0 - URL filtering"
        "jwt_tool:jwt_tool:Phase 4 - JWT testing"
    )

    local overall=0 missing=0
    for entry in "${tools[@]}"; do
        local name="${entry%%:*}"
        local binary="${entry#*:}"; binary="${binary%%:*}"
        local phase="${entry##*:}"
        if command -v "$binary" &>/dev/null; then
            echo "  [✓] $name ($phase)"
            ((overall++))
        else
            echo "  [✗] $name ($phase) — missing"
            ((missing++))
        fi
    done

    echo ""
    echo "---"
    echo "Total: $overall present, $missing missing"
    if [[ $missing -gt 0 ]]; then
        echo "Install missing tools via apt/pip3/go install or reconftw's install.sh"
    fi
}

main "$@"
