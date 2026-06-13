#!/usr/bin/env python3
"""Convert BH skills to OpenCode agents for Dristi.

Usage:
    python3 convert_skills.py <phase> [--dry-run]

Phases:
    1 = Core Web Hunters (29)
    2 = Enterprise Platform (11)
    3 = Support & Methodology (14)
    4 = Framework-Specific (7)
    5 = Specialized (10)
    all = all of the above

Output: $HOME/dristi/.opencode/agents/<agent-dir>/SKILL.md
"""

import re
import sys
import yaml
from pathlib import Path

HOME = Path.home()
BH_SKILLS = HOME / "dristi/skills"
AGENTS_DIR = HOME / "dristi/.opencode/agents"

# ── Phase 1: Core Web Hunters ───────────────────────────────────────────────
PHASE_1 = {
    "hunt-xss": {
        "agent": "xss-hunter",
        "description": "Cross-Site Scripting hunter. Reflected, stored, and DOM-based XSS, CSP bypass, mXSS, sanitizer evasion, polyglot payloads, cache-poison XSS chains, and postMessage gadgets.",
        "wstg": "INPV-01 (Reflected XSS), INPV-02 (Stored XSS), CLNT-01 (DOM XSS)",
        "dristi_prompt": "input-validation.md, client-side.md",
    },
    "hunt-sqli": {
        "agent": "sqli-hunter",
        "description": "SQL injection and NoSQL injection hunter. Classic SQLi, blind/time-based, second-order, ORM raw-fragment SQLi, MongoDB $regex/$where injection, CouchDB JavaScript injection, DynamoDB expression injection.",
        "wstg": "INPV-05 (SQL Injection), INPV-06 (NoSQL Injection)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-ssrf": {
        "agent": "ssrf-hunter",
        "description": "Server-Side Request Forgery hunter. Cloud metadata SSRF, blind OOB SSRF, URL parser bypass, redirect-based SSRF, and chain paths to RCE.",
        "wstg": "INPV-07 (SSRF)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-ssti": {
        "agent": "ssti-hunter",
        "description": "Server-Side Template Injection hunter. Jinja2, Twig, Freemarker, Velocity, Jade/Pug, ERB. Detection, context identification, RCE chains.",
        "wstg": "INPV-09 (Template Injection)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-lfi": {
        "agent": "lfi-hunter",
        "description": "Local File Inclusion / Path Traversal hunter. Directory traversal, RFI, PHP wrappers, log poisoning, and chain to RCE.",
        "wstg": "INPV-06 (Path Traversal)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-xxe": {
        "agent": "xxe-hunter",
        "description": "XML External Entity hunter. In-band XXE, blind OOB XXE, SVG XXE, XInclude attacks, docx/pptx XXE, SOAP XXE.",
        "wstg": "INPV-08 (XXE)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-idor": {
        "agent": "idor-hunter",
        "description": "Insecure Direct Object Reference hunter. UUID enumeration, sequential IDs, GraphQL IDOR, multi-tenant data access, mass assignment chaining, and parameter-based object reference bypass.",
        "wstg": "ATHZ-01 (IDOR)",
        "dristi_prompt": "authorization.md",
    },
    "hunt-csrf": {
        "agent": "csrf-hunter",
        "description": "Cross-Site Request Forgery hunter. Anti-CSRF token bypass, SameSite bypass, JSON Content-Type CSRF, multi-step CSRF, and chaining to ATO.",
        "wstg": "SESS-05 (CSRF)",
        "dristi_prompt": "session-management.md",
    },
    "hunt-cors": {
        "agent": "cors-hunter",
        "description": "CORS misconfiguration hunter. Origin reflection, wildcard origin with credentials, preflight bypass, null origin, and intranet CORS exploitation.",
        "wstg": "CLNT-07 (CORS)",
        "dristi_prompt": "client-side.md",
    },
    "hunt-oauth": {
        "agent": "oauth-hunter",
        "description": "OAuth 2.0 / OpenID Connect hunter. Redirect URI bypass, state nonce leakage, CSRF on OAuth flow, token leakage via Referer, implicit flow weaknesses.",
        "wstg": "ATHN-09 (OAuth), ATHN-10 (OIDC)",
        "dristi_prompt": "authentication.md",
    },
    "hunt-graphql": {
        "agent": "graphql-hunter",
        "description": "GraphQL API hunter. Introspection, batching attacks, alias abuse, depth-based DoS, auth bypass, IDOR in GraphQL resolvers, custom scalar injection.",
        "wstg": "APIT-01 (GraphQL)",
        "dristi_prompt": "api-testing.md",
    },
    "hunt-file-upload": {
        "agent": "file-upload-hunter",
        "description": "File upload vulnerability hunter. Unrestricted file upload, SVG XSS, polyglot files, Content-Type bypass, zip slip, race condition on upload.",
        "wstg": "BUSL-07 (File Upload), INPV-13 (Upload XSS)",
        "dristi_prompt": "business-logic.md, input-validation.md",
    },
    "hunt-host-header": {
        "agent": "host-header-hunter",
        "description": "Host header injection hunter. Password reset poisoning, cache poisoning, SSRF via Host header, routing-based SSRF, absolute URL injection.",
        "wstg": "CONF-06 (Host Header), INPV-16 (HTTP Host)",
        "dristi_prompt": "configuration.md, input-validation.md",
    },
    "hunt-http-smuggling": {
        "agent": "http-smuggler",
        "description": "HTTP request smuggling hunter. CL.TE, TE.CL, TE.TE variations, connection reuse poisoning, cache poisoning via smuggling, WAF bypass.",
        "wstg": "INPV-17 (HTTP Smuggling)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-open-redirect": {
        "agent": "open-redirect-hunter",
        "description": "Open redirect hunter. URL parser bypass, protocol confusion, CRLF injection in redirect, chaining to phishing/XSS, OAuth redirect abuse.",
        "wstg": "INPV-15 (Open Redirect)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-brute-force": {
        "agent": "brute-force-hunter",
        "description": "Brute force and credential stuffing hunter. Rate limiting bypass, JWT brute force, 2FA bypass via brute force, password policy bypass.",
        "wstg": "ATHN-07 (Weak Password Policy), ATHN-08 (Brute Force)",
        "dristi_prompt": "authentication.md",
    },
    "hunt-session": {
        "agent": "session-hunter",
        "description": "Session management flaw hunter. Session fixation, predictable tokens, weak cookie attributes, concurrent session handling, JWT session weaknesses.",
        "wstg": "SESS-01 through SESS-11 (Session Management)",
        "dristi_prompt": "session-management.md",
    },
    "hunt-auth-bypass": {
        "agent": "auth-bypass-hunter",
        "description": "Authentication bypass hunter. Forced browsing, HTTP method override, parameter pollution, direct endpoint access, role-based bypass.",
        "wstg": "ATHZ-02 (Authorization Bypass)",
        "dristi_prompt": "authorization.md",
    },
    "hunt-ato": {
        "agent": "ato-hunter",
        "description": "Account Takeover hunter. Password reset logic flaws, email takeover, OAuth token theft, 2FA bypass, session hijack, SSO bypass chains.",
        "wstg": "ATHN-10 (Account Enumeration), ATHN-11 (Credential Transport)",
        "dristi_prompt": "authentication.md",
    },
    "hunt-subdomain": {
        "agent": "subdomain-hunter",
        "description": "Subdomain takeover hunter. CNAME dangling, NS delegation, Azure/DNS/CloudFront/S3 takeover, expired DNS, dead link hijacking.",
        "wstg": "INFO-03 (Subdomain Enumeration), INFO-05 (DNS Recon)",
        "dristi_prompt": "info-gathering.md",
    },
    "hunt-api-misconfig": {
        "agent": "api-misconfig-hunter",
        "description": "API security misconfiguration hunter. Mass assignment, rate limiting gaps, excessive data exposure, improper asset management, auth on non-production APIs.",
        "wstg": "APIT-02 (REST), APIT-03 (SOAP)",
        "dristi_prompt": "api-testing.md",
    },
    "hunt-mfa-bypass": {
        "agent": "mfa-bypass-hunter",
        "description": "MFA bypass hunter. Push fatigue, backup code reuse, token reuse, biometric bypass, SIM swap chaining, rate limiting, social engineering vectors.",
        "wstg": "ATHN-09 (MFA/2FA Testing)",
        "dristi_prompt": "authentication.md",
    },
    "hunt-race-condition": {
        "agent": "race-condition-hunter",
        "description": "Race condition hunter. TOCTOU, payment race conditions, coupon/loyalty race, rate limit race, async race, database contention.",
        "wstg": "BUSL-04 (Race Conditions)",
        "dristi_prompt": "business-logic.md",
    },
    "hunt-cache-poison": {
        "agent": "cache-poison-hunter",
        "description": "Web cache poisoning hunter. Unkeyed inputs, CDN-specific poisoning (Cloudflare, Akamai, Fastly), cache deception, cache key injection.",
        "wstg": "CLNT-12 (Client-Side Cache), CONF-09 (Cache)",
        "dristi_prompt": "client-side.md, configuration.md",
    },
    "hunt-deserialization": {
        "agent": "deserialization-hunter",
        "description": "Insecure deserialization hunter. PHP unserialize, Java deserialization (ysoserial), .NET ViewState, pickle, Ruby MARSHAL, Node.js unserialize.",
        "wstg": "INPV-10 (Deserialization)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-dom": {
        "agent": "dom-hunter",
        "description": "DOM-based vulnerability hunter. DOM XSS, DOM clobbering, DOM injection, prototype pollution, trusted types bypass, client-side template injection.",
        "wstg": "CLNT-01 (DOM XSS), CLNT-05 (DOM Injection)",
        "dristi_prompt": "client-side.md",
    },
    "hunt-websocket": {
        "agent": "websocket-hunter",
        "description": "WebSocket security hunter. WS message injection, origin bypass, CSWSH, WS proxy misconfig, cross-origin WebSocket hijacking, WS tunneling.",
        "wstg": "CLNT-11 (WebSocket)",
        "dristi_prompt": "client-side.md",
    },
    "hunt-llm-ai": {
        "agent": "llm-hunter",
        "description": "LLM/AI security hunter. Prompt injection, RAG poisoning, model data extraction, jailbreak detection, indirect prompt injection via tools, MCP server abuse.",
        "wstg": "OWASP LLM Top 10, INPV-20 (LLM Input Validation)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-rce": {
        "agent": "rce-hunter",
        "description": "Remote Code Execution hunter. Command injection (OS), eval() injection, SSTI chained to RCE, file write to RCE, dependency RCE, library injection.",
        "wstg": "INPV-03 (Command Injection), INPV-10 (Code Injection)",
        "dristi_prompt": "input-validation.md",
    },
}

# ── Phase 2: Enterprise Platform ────────────────────────────────────────────
PHASE_2 = {
    "cloud-iam-deep": {
        "agent": "cloud-iam-auditor",
        "description": "Cloud IAM privilege escalation auditor. AWS IAM priv-esc (24+ patterns), Azure RBAC abuse, GCP IAM misconfig, cross-account role trust, managed policy exploitation.",
        "wstg": "CONF-10 (Cloud Config)",
        "dristi_prompt": "configuration.md",
    },
    "m365-entra-attack": {
        "agent": "m365-attacker",
        "description": "Microsoft 365 / Entra ID attack chains. AADSTS error analysis, Smart Lockout math, Conditional Access bypass, token theft, device registration abuse, hybrid identity.",
        "wstg": "ATHN-11 (Cloud Auth), IDNT-04 (Federation)",
        "dristi_prompt": "authentication.md, identity-management.md",
    },
    "okta-attack": {
        "agent": "okta-attacker",
        "description": "Okta identity platform attack chains. Okta-as-IdP misconfig, SWA injection, delegated authentication flaws, API token abuse, event hook manipulation.",
        "wstg": "ATHN-11 (SAML/OIDC), IDNT-04 (Federation)",
        "dristi_prompt": "authentication.md, identity-management.md",
    },
    "vmware-vcenter-attack": {
        "agent": "vcenter-attacker",
        "description": "VMware vCenter exploitation chains. CVE-2021-21972 through CVE-2024-37085, vCenter to ESXI lateral movement, vCenter SSO bypass, vulnerable appliance exploitation.",
        "wstg": "CONF-03 (Infrastructure Config)",
        "dristi_prompt": "configuration.md",
    },
    "enterprise-vpn-attack": {
        "agent": "vpn-attacker",
        "description": "Enterprise VPN exploitation. Cisco ASA/FTD, Fortinet FortiGate, Citrix ADC/Gateway, Palo Alto PAN-OS, Pulse Secure, SonicWall, F5 Big-IP CVEs and config weaknesses.",
        "wstg": "CONF-03 (Infrastructure Config)",
        "dristi_prompt": "configuration.md",
    },
    "hunt-k8s": {
        "agent": "k8s-hunter",
        "description": "Kubernetes security hunter. RBAC abuse, pod escape, secrets exposure, kubelet API, etcd access, admission controller bypass, container breakout chains.",
        "wstg": "CONF-10 (Container Security)",
        "dristi_prompt": "configuration.md",
    },
    "hunt-cicd": {
        "agent": "cicd-hunter",
        "description": "CI/CD pipeline hunter. GitHub Actions injection, GitLab CI abuse, Jenkins pipeline groovy, self-hosted runner compromise, artifact poisoning, secret exposure.",
        "wstg": "CONF-11 (CI/CD Security)",
        "dristi_prompt": "configuration.md",
    },
    "hunt-cloud-misconfig": {
        "agent": "cloud-misconfig-hunter",
        "description": "Cloud storage misconfiguration hunter. Open S3/Azure Blob/GCP buckets, public AMIs, unsecured databases, cloud metadata exposure, snapshot sharing.",
        "wstg": "CONF-10 (Cloud Config)",
        "dristi_prompt": "configuration.md",
    },
    "apk-redteam-pipeline": {
        "agent": "apk-analyzer",
        "description": "Android APK red team pipeline. APK acquisition, decompile (jadx/apktool), secret grep, Frida instrumentation, certificate pinning bypass, intent analysis.",
        "wstg": "MOB-01 through MOB-09 (Mobile Security)",
        "dristi_prompt": "client-side.md",
    },
    "supply-chain-attack-recon": {
        "agent": "supply-chain-hunter",
        "description": "Supply chain attack recon. Dependency confusion, package squatting, typosquatting, GH Actions dependency injection, SBOM mining, mirror/pypi/gem/npm registry poisoning.",
        "wstg": "CONF-12 (Supply Chain Security)",
        "dristi_prompt": "configuration.md",
    },
    "hunt-sharepoint": {
        "agent": "sharepoint-hunter",
        "description": "SharePoint security hunter. SharePoint on-prem/online misconfiguration, privilege escalation, exposed web parts, workflow abuse, viewstate deserialization.",
        "wstg": "CONF-04 (SharePoint), ATHZ-02 (Privilege Escalation)",
        "dristi_prompt": "configuration.md, authorization.md",
    },
    "hunt-ntlm-info": {
        "agent": "ntlm-hunter",
        "description": "NTLM information disclosure hunter. NTLM challenge capture, relay primitives, coercion, NetNTLMv2 interception, HTTP NTLM auth exposure.",
        "wstg": "INFO-09 (NTLM Leak), CONF-08 (Auth Headers)",
        "dristi_prompt": "info-gathering.md, configuration.md",
    },
}

# ── Phase 3: Support & Methodology ──────────────────────────────────────────
PHASE_3 = {
    "bb-methodology": {
        "agent": "bb-methodology",
        "description": "Bug bounty methodology orchestrator. 5-phase nonlinear workflow, mode selection (bounty/redteam/pentest/audit), scope confirmation, throttle management, payout optimization.",
        "wstg": "All phases (Workflow Orchestration)",
        "dristi_prompt": "all prompts/",
    },
    "hunt-dispatch": {
        "agent": "hunt-dispatcher",
        "description": "Hunt dispatcher — routes to the correct hunting agent based on target fingerprinting. Mode selection, technology stack identification, agent delegation.",
        "wstg": "INFO-01 (Fingerprinting), INFO-02 (Technology Detection)",
        "dristi_prompt": "info-gathering.md",
    },
    "report-writing": {
        "agent": "report-writing",
        "description": "Security report writer. HackerOne/Bugcrowd/Intigriti/Immunefi templates, impact quantification, CVSS 3.1 scoring, remediation guidance, executive summaries.",
        "wstg": "All phases (Report Generation)",
        "dristi_prompt": "templates/report-template.md",
    },
    "triage-validation": {
        "agent": "triage-validation",
        "description": "Finding triage and validation. 7-Question Gate: real request? accepted impact? in-scope? not admin-only? concrete? not on never-submit? Verdicts: PASS/KILL/DOWNGRADE/CHAIN-REQUIRED.",
        "wstg": "All phases (Validation Gate)",
        "dristi_prompt": "templates/quality-gates.md",
    },
    "evidence-hygiene": {
        "agent": "evidence-hygiene",
        "description": "Evidence hygiene specialist. Cookie/PII redaction, HAR sanitization, screenshot metadata stripping, evidence chain of custody, submission proof pack.",
        "wstg": "All phases (Evidence Handling)",
        "dristi_prompt": "templates/testing-strategies.md",
    },
    "offensive-osint": {
        "agent": "offensive-osint",
        "description": "Offensive OSINT gatherer. Identity fabric mapping, breached credential lookup, email/phone/social enumeration, dark web intel, organizational footprint.",
        "wstg": "INFO-01 (Search Engine Recon), INFO-02 (OSINT), INFO-06 (Information Leak)",
        "dristi_prompt": "info-gathering.md",
    },
    "web2-recon": {
        "agent": "web2-recon",
        "description": "Web recon specialist. Subdomain enumeration, technology fingerprinting, endpoint discovery, directory brute force, parameter fuzzing, WAF detection.",
        "wstg": "INFO-03 through INFO-10 (Recon Techniques)",
        "dristi_prompt": "info-gathering.md",
    },
    "osint-methodology": {
        "agent": "osint-methodology",
        "description": "OSINT methodology guide. Source verification, data correlation, persona tracking, geolocation, temporal analysis, OSINT tool selection framework.",
        "wstg": "INFO-01, INFO-02, INFO-06",
        "dristi_prompt": "info-gathering.md",
    },
    "redteam-mindset": {
        "agent": "redteam-mindset",
        "description": "Red team operator mindset. Primary directive, anti-patterns, operational discipline, burnout avoidance, documentation hygiene, engagement closure discipline.",
        "wstg": "All phases (Operator Guidance)",
        "dristi_prompt": "all prompts/",
    },
    "mid-engagement-ir-detection": {
        "agent": "ir-detector",
        "description": "Mid-engagement IR/defender detection awareness. SOC detection patterns, blue team tooling, EDR telemetry, defender response playbooks, operational stealth.",
        "wstg": "All phases (OPSEC)",
        "dristi_prompt": "templates/testing-strategies.md",
    },
    "redteam-report-template": {
        "agent": "redteam-reporter",
        "description": "Red team report template generator. Client-facing DOCX deliverables, Subject/Observations/Impact/Recommendation/PoC sections, embedded screenshots, executive summary.",
        "wstg": "All phases (Red Team Reporting)",
        "dristi_prompt": "templates/report-template.md",
    },
    "bugcrowd-reporting": {
        "agent": "bugcrowd-reporter",
        "description": "Bugcrowd-specific reporter. VRT category mapping, severity justification, OOS rebuttal templates, Bugcrowdninja alias hygiene, friendly-tester posture guidelines.",
        "wstg": "All phases (Bugcrowd Reporting)",
        "dristi_prompt": "templates/report-template.md",
    },
    "bug-bounty": {
        "agent": "bug-bounty",
        "description": "Bug bounty generalist orchestrator. Program selection, duplicate detection, payout optimization, VRT mapping, responsible disclosure, bounty hunter workflow.",
        "wstg": "All phases (Bug Bounty)",
        "dristi_prompt": "all prompts/",
    },
    "security-arsenal": {
        "agent": "security-arsenal",
        "description": "Security tool arsenal reference. Payload banks, wordlists, tool configuration profiles, one-liner collections, WAF bypass lists, encoding/decoding reference.",
        "wstg": "All phases (Tool Reference)",
        "dristi_prompt": "all prompts/",
    },
}

# ── Phase 4: Framework-Specific ─────────────────────────────────────────────
PHASE_4 = {
    "hunt-aspnet": {
        "agent": "aspnet-hunter",
        "description": "ASP.NET / .NET security hunter. ViewState validation bypass, machineKey disclosure, IIS misconfig, UnvalidatedRequestValues, request validation bypass (CVE-2024-22093).",
        "wstg": "CONF-04 (.NET Config), INPV-05 (ASP.NET Injection)",
        "dristi_prompt": "configuration.md, input-validation.md",
    },
    "hunt-springboot": {
        "agent": "springboot-hunter",
        "description": "Spring Boot security hunter. Actuator exposure, Spring4Shell, classpath RCE, property injection, Spring Cloud/Config vulnerabilities, SpEL injection.",
        "wstg": "CONF-05 (Java/Spring Config), INPV-10 (SpEL Injection)",
        "dristi_prompt": "configuration.md, input-validation.md",
    },
    "hunt-laravel": {
        "agent": "laravel-hunter",
        "description": "Laravel security hunter. Debug mode exposure, APP_KEY decryption, serialization RCE, mass assignment, Blade template injection, Eloquent injection.",
        "wstg": "CONF-04 (PHP Config), INPV-05 (Eloquent Injection)",
        "dristi_prompt": "configuration.md, input-validation.md",
    },
    "hunt-nextjs": {
        "agent": "nextjs-hunter",
        "description": "Next.js security hunter. Vercel misconfig, SSG/SSR data leakage, API route auth bypass, middleware bypass, image optimization abuse, RSC injection.",
        "wstg": "CONF-04 (Node.js Config), APIT-02 (Next.js API)",
        "dristi_prompt": "configuration.md, api-testing.md",
    },
    "hunt-nodejs": {
        "agent": "nodejs-hunter",
        "description": "Node.js/Express security hunter. Prototype pollution, unsafe eval, deserialization, dependency vulnerability, misconfigured CORS, express-session flaws.",
        "wstg": "INPV-10 (Prototype Pollution), INPV-03 (Code Injection)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-tls-network": {
        "agent": "tls-hunter",
        "description": "TLS/SSL and network security hunter. Weak cipher suites, outdated TLS versions, certificate validation bypass, STARTTLS injection, HTTP/2 downgrade.",
        "wstg": "CRYP-01 (Weak TLS), CRYP-02 (Padding Oracle), CRYP-03 (Weak Crypto)",
        "dristi_prompt": "cryptography.md",
    },
}

# ── Phase 5: Specialized ────────────────────────────────────────────────────
PHASE_5 = {
    "hunt-nosqli": {
        "agent": "nosqli-hunter",
        "description": "NoSQL injection hunter. MongoDB $where/$regex injection, CouchDB JavaScript injection, Cassandra CQL injection, DynamoDB expression injection.",
        "wstg": "INPV-06 (NoSQL Injection)",
        "dristi_prompt": "input-validation.md",
    },
    "hunt-saml": {
        "agent": "saml-hunter",
        "description": "SAML SSO hunter. XML signature wrapping, assertion injection, Replay attack, recipient/audience confusion, IDP-initiated SSO abuse, certificate manipulation.",
        "wstg": "ATHN-10 (SAML), IDNT-04 (Federation)",
        "dristi_prompt": "authentication.md, identity-management.md",
    },
    "hunt-ldap": {
        "agent": "ldap-hunter",
        "description": "LDAP injection and security hunter. LDAP injection, anonymous binds, privilege escalation via LDAP, directory traversal, AD/LDAP misconfig.",
        "wstg": "INPV-11 (LDAP Injection), CONF-07 (Directory Services)",
        "dristi_prompt": "input-validation.md, configuration.md",
    },
    "hunt-source-leak": {
        "agent": "hunt-source-leak",
        "description": "Source code leak hunter. .git/config exposure, .env file access, backup file disclosure, source map/reverse source map analysis, debug endpoint exposure.",
        "wstg": "INFO-06 (Information Leak), CONF-02 (File Exposure)",
        "dristi_prompt": "info-gathering.md, configuration.md",
    },
    "hunt-business-logic": {
        "agent": "bizlogic-hunter",
        "description": "Business logic flaw hunter. Pricing manipulation, workflow bypass, multi-step process flaws, currency conversion exploits, loyalty/coupon abuse, KYC bypass.",
        "wstg": "BUSL-01 through BUSL-10 (Business Logic)",
        "dristi_prompt": "business-logic.md",
    },
    "hunt-misc": {
        "agent": "misc-hunter",
        "description": "General vulnerability hunter. Catch-all for uncovered classes, emerging threats, zero-day patterns, uncommon attack surfaces, and novel vulnerability types.",
        "wstg": "All categories (General)",
        "dristi_prompt": "all prompts/",
    },
    "web3-audit": {
        "agent": "web3-audit",
        "description": "Web3/blockchain audit hunter. 10 DeFi bug classes: reentrancy, flash loan, oracle manipulation, sandwich attack, MEV extraction, access control, integer overflow, signature replay.",
        "wstg": "DeFi Security (10 Bug Classes)",
        "dristi_prompt": "input-validation.md, business-logic.md",
    },
    "meme-coin-audit": {
        "agent": "meme-coin-auditor",
        "description": "Meme coin / token audit hunter. Token rug-pull detection, honeypot analysis, liquidity lock verification, ownership renounce, proxy contract risks.",
        "wstg": "DeFi Security (Token Risks)",
        "dristi_prompt": "business-logic.md",
    },
}

# ── WSTG cross-reference by agent name ──────────────────────────────────────
WSTG_TESTS = {
    "xss-hunter": "WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01",
    "sqli-hunter": "WSTG-INPV-05, WSTG-INPV-06",
    "ssrf-hunter": "WSTG-INPV-07",
    "ssti-hunter": "WSTG-INPV-09",
    "lfi-hunter": "WSTG-INPV-06",
    "xxe-hunter": "WSTG-INPV-08",
    "idor-hunter": "WSTG-ATHZ-01",
    "csrf-hunter": "WSTG-SESS-05",
    "cors-hunter": "WSTG-CLNT-07",
    "oauth-hunter": "WSTG-ATHN-09",
    "graphql-hunter": "WSTG-APIT-01",
    "file-upload-hunter": "WSTG-BUSL-07",
    "host-header-hunter": "WSTG-INPV-16",
    "http-smuggler": "WSTG-INPV-17",
    "open-redirect-hunter": "WSTG-INPV-15",
    "brute-force-hunter": "WSTG-ATHN-07",
    "session-hunter": "WSTG-SESS-*",
    "auth-bypass-hunter": "WSTG-ATHZ-02",
    "ato-hunter": "WSTG-ATHN-10",
    "subdomain-hunter": "WSTG-INFO-03",
    "api-misconfig-hunter": "WSTG-APIT-02",
    "mfa-bypass-hunter": "WSTG-ATHN-09",
    "race-condition-hunter": "WSTG-BUSL-04",
    "cache-poison-hunter": "WSTG-CLNT-12",
    "deserialization-hunter": "WSTG-INPV-10",
    "dom-hunter": "WSTG-CLNT-01",
    "websocket-hunter": "WSTG-CLNT-11",
    "llm-hunter": "WSTG-INPV-20",
    "rce-hunter": "WSTG-INPV-03",
}


def _fix_acronyms(text: str) -> str:
    """Fix acronym casing: Xss -> XSS, Sqli -> SQLi, etc."""
    fixes = {
        "Xss": "XSS",
        "Sqli": "SQLi",
        "Ssrf": "SSRF",
        "Ssti": "SSTI",
        "Lfi": "LFI",
        "Xxe": "XXE",
        "Idor": "IDOR",
        "Csrf": "CSRF",
        "Cors": "CORS",
        "Oauth": "OAuth",
        "Graphql": "GraphQL",
        "Ato": "ATO",
        "Mfa": "MFA",
        "Dom": "DOM",
        "Rce": "RCE",
        "Nosqli": "NoSQLi",
        "Hpp": "HPP",
        "Hpf": "HPF",
        "Tls": "TLS",
        "Ntlm": "NTLM",
        "Saml": "SAML",
        "Ldap": "LDAP",
        "Spel": "SpEL",
        "AspNet": "ASP.NET",
        "K8S": "K8s",
        "Cicd": "CI/CD",
        "Llm": "LLM",
        "Ai": "AI",
        "Api": "API",
        "Cdn": "CDN",
        "Dns": "DNS",
        "Url": "URL",
        "Waf": "WAF",
        "Jwt": "JWT",
        "Csp": "CSP",
        "Mxss": "mXSS",
        "Svg": "SVG",
        "Ssl": "SSL",
        "Sso": "SSO",
        "Rbac": "RBAC",
        "Cve": "CVE",
        "Cvss": "CVSS",
        "Poc": "PoC",
        "Oob": "OOB",
        "Or Ntl": "or NTLM",
    }
    for wrong, correct in fixes.items():
        text = text.replace(wrong, correct)
    return text

# Maps old BH skill references to Dristi equivalents
BH_TO_DRISTI = {
    "hunt-xss": "xss-hunter",
    "hunt-sqli": "sqli-hunter",
    "hunt-ssrf": "ssrf-hunter",
    "hunt-ssti": "ssti-hunter",
    "hunt-lfi": "lfi-hunter",
    "hunt-xxe": "xxe-hunter",
    "hunt-idor": "idor-hunter",
    "hunt-csrf": "csrf-hunter",
    "hunt-cors": "cors-hunter",
    "hunt-oauth": "oauth-hunter",
    "hunt-graphql": "graphql-hunter",
    "hunt-file-upload": "file-upload-hunter",
    "hunt-host-header": "host-header-hunter",
    "hunt-http-smuggling": "http-smuggler",
    "hunt-open-redirect": "open-redirect-hunter",
    "hunt-brute-force": "brute-force-hunter",
    "hunt-session": "session-hunter",
    "hunt-auth-bypass": "auth-bypass-hunter",
    "hunt-ato": "ato-hunter",
    "hunt-subdomain": "subdomain-hunter",
    "hunt-api-misconfig": "api-misconfig-hunter",
    "hunt-mfa-bypass": "mfa-bypass-hunter",
    "hunt-race-condition": "race-condition-hunter",
    "hunt-cache-poison": "cache-poison-hunter",
    "hunt-deserialization": "deserialization-hunter",
    "hunt-dom": "dom-hunter",
    "hunt-websocket": "websocket-hunter",
    "hunt-llm-ai": "llm-hunter",
    "hunt-rce": "rce-hunter",
    "hunt-k8s": "k8s-hunter",
    "hunt-cicd": "cicd-hunter",
    "hunt-cloud-misconfig": "cloud-misconfig-hunter",
    "hunt-nosqli": "nosqli-hunter",
    "hunt-saml": "saml-hunter",
    "hunt-ldap": "ldap-hunter",
    "source-leak-hunter": "hunt-source-leak",
    "hunt-business-logic": "bizlogic-hunter",
    "hunt-misc": "misc-hunter",
    "hunt-sharepoint": "sharepoint-hunter",
    "hunt-ntlm-info": "ntlm-hunter",
    "hunt-aspnet": "aspnet-hunter",
    "hunt-springboot": "springboot-hunter",
    "hunt-laravel": "laravel-hunter",
    "hunt-nextjs": "nextjs-hunter",
    "hunt-nodejs": "nodejs-hunter",
    "hunt-tls-network": "tls-hunter",
    "security-arsenal": "security-arsenal",
    "triage-validator": "triage-validation",
    "report-writer": "report-writing",
    "evidence-hygiene": "evidence-hygiene",
    "osint-gatherer": "offensive-osint",
    "web-recon": "web2-recon",
    "osint-methodology": "osint-methodology",
    "bb-methodology": "bb-methodology",
    "bug-bounty": "bug-bounty",
    "bugcrowd-reporting": "bugcrowd-reporter",
    "redteam-mindset": "redteam-mindset",
    "mid-engagement-ir-detection": "ir-detector",
    "redteam-report-template": "redteam-reporter",
    "cloud-iam-deep": "cloud-iam-auditor",
    "m365-entra-attack": "m365-attacker",
    "okta-attack": "okta-attacker",
    "vmware-vcenter-attack": "vcenter-attacker",
    "enterprise-vpn-attack": "vpn-attacker",
    "supply-chain-attack-recon": "supply-chain-hunter",
    "apk-redteam-pipeline": "apk-analyzer",
    "web3-auditor": "web3-audit",
    "meme-coin-audit": "meme-coin-auditor",
    "hunt-dispatch": "hunt-dispatcher",
}


HEADER_TEMPLATE = """\
---
description: {description}
mode: subagent
permission:
  read: allow
  bash: deny
  edit: deny
  grep: allow
  glob: allow
---

You are an expert {short_name} for penetration testing.

## Workflow Integration with Dristi

This agent works alongside the Dristi MCP server and WSTG methodology:

1. **Read the methodology** → `get_wstg_test("{wstg_test_id}")` for baseline technique guidance
2. **Check related prompt** → read `prompts/{dristi_prompt}` for Dristi-specific workflow
3. **BurpSuite pro workflow** — Use Burp MCP tools at every stage like a professional bug hunter. All HTTP requests flow through Burp (NOT raw curl). The workflow mirrors real Burp usage:

   a) **Proxy** — Intercept and review all traffic:
      - `burp_set_proxy_intercept_state(True/False)` — toggle intercept to pause/resume requests in-flight
      - `burp_get_proxy_http_history()` — review discovered endpoints, params, and auth tokens in history
      - `burp_get_active_editor_contents()` — read the current request in the editor
      - `burp_set_active_editor_contents(text)` — modify a request in the editor before forwarding

   b) **Repeater** — Manual testing on interesting endpoints:
      - `burp_send_http1_request(content, targetHostname, targetPort, usesHttps)` — fire a single HTTP/1.1 request
      - `burp_send_http2_request(headers, pseudoHeaders, requestBody, ...)` — fire a single HTTP/2 request
      - `burp_create_repeater_tab(content, targetHostname, targetPort, usesHttps, tabName)` — save request/response to a named Repeater tab for review
      - `burp_create_repeater_tab_http2(headers, pseudoHeaders, requestBody, targetHostname, targetPort, usesHttps, tabName)` — save HTTP/2 finding to Repeater

   c) **Intruder** — Automated fuzzing and enumeration:
      - `burp_send_to_intruder(content, targetHostname, targetPort, usesHttps, tabName)` — send request to Intruder for parameter fuzzing, brute force, or ID enumeration

   d) **Collaborator** — Out-of-band detection:
      - `burp_generate_collaborator_payload()` — get a unique collaborator URL for OOB testing (blind XSS, SSRF, XXE, SQLi)
      - `burp_get_collaborator_interactions(payloadId)` — poll for DNS/HTTP/SMTP callbacks from the target

   e) **Scanner** — Automated vulnerability scanning:
      - `burp_get_scanner_issues()` — retrieve scan findings (filter by severity)

   f) **Organizer** — Evidence storage for reporting:
      - `burp_get_organizer_items(count, offset)` — retrieve saved items from Organizer
      - `burp_get_organizer_items_regex(count, offset, regex)` — search Organizer by pattern
4. **Find vulnerabilities** → `log_finding()` or `findings_add_vuln()` to persist to SQLite
5. **Log findings** → `findings_add_vuln(engagement_id, title, severity, ..., test_id="{wstg_test_id}")`
6. **Track coverage** → `track_test(engagement_id, test_id="{wstg_test_id}", status="completed", notes=...)`
7. **Chain findings** → `findings_add_chain()` to record multi-step attack paths
8. **Generate report** → `findings_handoff()` for cross-session handoff or `generate_report()` for final output

## Scope Notice

- **Advisory mode** (default): You provide methodology, payloads, and analysis. The user executes commands.
- **Execution mode**: If the user has a declared scope in Dristi (`findings_init()`), you may compose commands for the user to run.

---

## {title}

"""


def convert_skill(skill_dir: str, config: dict, dry_run: bool = False) -> str:
    """Convert a single BH skill to OpenCode agent."""
    skill_path = BH_SKILLS / skill_dir / "SKILL.md"
    if not skill_path.exists():
        print(f"  [SKIP] {skill_path} not found")
        return ""

    content = skill_path.read_text(encoding="utf-8")

    # Parse YAML frontmatter - handle problematic descriptions with colons
    parts = content.split("---", 2)
    frontmatter = {}
    try:
        frontmatter = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        # Fallback: extract fields manually using regex
        fm_text = parts[1]
        name_m = re.search(r'^name:\s*(.+)$', fm_text, re.MULTILINE)
        desc_m = re.search(r'^description:\s*(.+)$', fm_text, re.MULTILINE)
        if name_m:
            frontmatter['name'] = name_m.group(1).strip()
        if desc_m:
            frontmatter['description'] = desc_m.group(1).strip()
    body = parts[2].strip()

    agent_name = config["agent"]
    description = config["description"]
    wstg = config.get("wstg", "")
    dristi_prompt = config.get("dristi_prompt", "")

    # Get a human-readable title from the skill name
    title_parts = skill_dir.replace("hunt-", "").replace("-", " ").title()
    if title_parts.startswith("Hunt "):
        title_parts = title_parts[5:]
    title_parts = _fix_acronyms(title_parts)
    title = title_parts + " Testing"

    short_name = agent_name.replace("-hunter", "").replace("-auditor", "").replace("-analyzer", "").replace("-attacker", "").replace("-reporter", "").replace("-detector", "").replace("-gatherer", "").replace("-recon", "").replace("-dispatcher", "").replace("-validator", "").replace("-writer", "").replace("-smuggler", "").replace("-methodology", "")

    # Build WSTG test ID reference
    wstg_first = wstg.split(",")[0].strip() if wstg else "WSTG"
    wstg_test_id = WSTG_TESTS.get(agent_name, wstg_first)

    # Build header
    header = HEADER_TEMPLATE.format(
        description=description,
        short_name=short_name,
        wstg_test_id=wstg_test_id,
        dristi_prompt=dristi_prompt,
        title=title,
    )

    # Rewrite cross-references in the body
    body = _rewrite_refs(body)

    # Fix Dristi MCP tool references
    body = _fix_tool_refs(body)

    agent_content = header + body

    if dry_run:
        print(f"  [OK] {agent_name} (would write to {AGENTS_DIR}/{agent_name}/SKILL.md)")
        return ""

    # Write to dir/SKILL.md
    agent_dir = AGENTS_DIR / agent_name
    agent_dir.mkdir(parents=True, exist_ok=True)
    agent_path = agent_dir / "SKILL.md"
    agent_path.write_text(agent_content, encoding="utf-8")
    lines = len(agent_content.splitlines())
    print(f"  [OK] {agent_name}/SKILL.md ({lines} lines)")
    return agent_name


def _rewrite_refs(body: str) -> str:
    """Rewrite BH cross-references to Dristi agent names."""
    for old_ref, new_ref in sorted(BH_TO_DRISTI.items(), key=lambda x: -len(x[0])):
        body = body.replace(f"`{old_ref}`", f"`{new_ref}`")
        body = body.replace(f"[{old_ref}]", f"[{new_ref}]")
    body = body.replace("Claude-BugHunter", "Dristi")
    body = body.replace("triage-validation", "triage-validator")
    body = body.replace("hunt-dispatch", "hunt-dispatcher")
    body = body.replace("bb-methodology", "bb-methodology")
    return body


def _fix_tool_refs(body: str) -> str:
    """Replace Claude Code tool refs with Dristi MCP equivalents."""
    replacements = [
        (r"`claude`", "`opencode`"),
    ]
    for old, new in replacements:
        body = body.replace(old, new)
    return body


def process_phase(phase_name: str, skills: dict, dry_run: bool = False) -> list:
    """Process all skills in a phase."""
    print(f"\n{'='*60}")
    print(f"Phase: {phase_name}")
    print(f"{'='*60}")
    converted = []
    for skill_dir, config in skills.items():
        result = convert_skill(skill_dir, config, dry_run)
        if result:
            converted.append(result)
    print(f"  Total: {len(converted)}/{len(skills)} converted")
    return converted


def main():
    dry_run = "--dry-run" in sys.argv

    phases_arg = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "--dry-run" else "all"

    AGENTS_DIR.mkdir(parents=True, exist_ok=True)

    phase_map = {
        "1": ("Core Web Hunters", PHASE_1),
        "2": ("Enterprise Platform", PHASE_2),
        "3": ("Support & Methodology", PHASE_3),
        "4": ("Framework-Specific", PHASE_4),
        "5": ("Specialized", PHASE_5),
        "all": ("All Phases", {**PHASE_1, **PHASE_2, **PHASE_3, **PHASE_4, **PHASE_5}),
    }

    if phases_arg not in phase_map:
        print(f"Usage: {sys.argv[0]} <phase|all> [--dry-run]")
        print(f"  Phases: {', '.join(k for k in phase_map if k != 'all')}, all")
        sys.exit(1)

    name, skills = phase_map[phases_arg]
    if dry_run:
        print(f"[DRY RUN] Would convert {len(skills)} skills\n")

    total = 0
    result = process_phase(name, skills, dry_run)
    total += len(result)

    print(f"\n{'='*60}")
    print(f"Summary: {total}/{len(skills)} agents created in {AGENTS_DIR}")
    if dry_run:
        print("(dry run — no files written)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
