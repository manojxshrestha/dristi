# Test Flow — Mastering Dristi

All interactions use `@agent-name` — no `/commands`. 8 pipeline agents on Tab: `@autopilot` → `@scope` → `@recon` → `@surface` → `@hunt` → `@capture` → `@validate` → `@report`. 48 specialized `@hunt-*` agents + 18 non-hunt agents (74 total) via `@`.

## Guided Flow

```
SCOPE complete?    ──→  "Ready to recon? → @recon target.com"
RECON complete?    ──→  "Ready to rank surface? → @surface target.com"
SURFACE ranked?    ──→  "Ready to hunt? → @hunt target.com"
HUNT complete?     ──→  "Found something? → @validate"
VALIDATE pass?     ──→  "Ready to report? → @report"
REPORT done?       ──→  "Loop back to hunt for more findings"
```

If stuck: just say *"What should I do next?"*

---

## The 7-Phase Pipeline

```
SCOPE → RECON → SURFACE → HUNT → CAPTURE → VALIDATE → REPORT
```

### P1: SCOPE — Define the Target

| Step | Action | What Happens |
|------|--------|--------------|
| 1 | Invoke `@scope` | Interactive scope walkthrough |
| 2 | Provide platform (H1/Bugcrowd/Intigriti/Other) | Report template selected per platform |
| 3 | List in-scope assets, out-of-scope items | `register_scope()` or `register_scope_batch()` via MCP |
| 4 | Paste full scope table | `parse_scope_table()` → registers all at once |
| 5 | Provide test credentials (optional) | Held in session memory |
| 6 | For deep scope methodology | `@bug-bounty` (program rules), `@osint-methodology` (OSINT expansion) |

**→ Transition:** Agent prompts *"Scope registered. Ready to recon? → @recon"*

---

### P2: RECON — Discover Endpoints

| Step | Action | What Happens |
|------|--------|--------------|
| 1 | `@recon` | Interactive recon: subdomains → live → crawl → params → cariddi → nuclei → secrets → vhost → cloud → takeover → zone → dorks |
| 2 | Or quick combined recon | `bash scripts/tools/auto_recon.sh <target>` or `bash scripts/tools/recon_engine.sh <target>` |
| 3 | Inspect results | Attack surface understood |
| 4 | For deeper recon | `@web2-recon`, `@offensive-osint`, `@osint-methodology` |

**→ Transition:** *"Recon complete. Ready to rank surface? → @surface"*

---

### P3: SURFACE — Ranked Attack Surface

| Step | Action | What Happens |
|------|--------|--------------|
| 1 | `@surface` | P1/P2/P3/Kill List — ranked by impact |
| 2 | Review P1 (API/GraphQL), P2 (upload/auth), P3 (all classes) | Know where to start |

**→ Transition:** *"Surface ranked. Ready to hunt? → @hunt"*

---

### P4: HUNT — Active Vulnerability Testing

Invoke `@hunt` or jump directly to a specific `@hunt-*` agent:

| Target | Agent |
|--------|-------|
| XSS | `@hunt-xss` |
| SQLi | `@hunt-sqli` |
| SSRF | `@hunt-ssrf` |
| IDOR | `@hunt-idor` |
| SSTI | `@hunt-ssti` |
| LFI/RFI | `@hunt-lfi` |
| RCE/CMDI | `@hunt-rce` |
| Auth bypass | `@hunt-auth-bypass` |
| ATO | `@hunt-ato` |
| API misconfig | `@hunt-api-misconfig` |
| GraphQL | `@hunt-graphql` |
| File upload | `@hunt-file-upload` |
| Race condition | `@hunt-race-condition` |
| OAuth | `@hunt-oauth` |
| CORS | `@hunt-cors` |
| XXE | `@hunt-xxe` |
| CSRF | `@hunt-csrf` |
| Prototype pollution | `@hunt-nodejs` / `@hunt-dom` |
| NoSQLi | `@hunt-nosqli` |
| LDAPi | `@hunt-ldap` |
| Open redirect | `@hunt-open-redirect` |
| HTTP smuggling | `@hunt-http-smuggling` |
| Deserialization | `@hunt-deserialization` |
| Subdomain takeover | `@hunt-subdomain` |
| JWT confusion | `@hunt-jwt-confusion` |
| Host header | `@hunt-host-header` |
| WebSocket | `@hunt-websocket` |
| NTLM info disclosure | `@hunt-ntlm-info` |
| LLM/AI | `@hunt-llm-ai` |
| Cache poison | `@hunt-cache-poison` |
| Brute force | `@hunt-brute-force` |
| Business logic | `@hunt-business-logic` |
| CI/CD | `@hunt-cicd` |
| Cloud misconfig | `@hunt-cloud-misconfig` |
| ASP.NET | `@hunt-aspnet` |
| Laravel | `@hunt-laravel` |
| Spring Boot | `@hunt-springboot` |
| Next.js | `@hunt-nextjs` |
| Node.js | `@hunt-nodejs` |
| SAML | `@hunt-saml` |
| Session mgmt | `@hunt-session` |
| SharePoint | `@hunt-sharepoint` |
| Source leak | `@hunt-source-leak` |
| MFA bypass | `@hunt-mfa-bypass` |
| TLS/SSL | `@hunt-tls-network` |
| Misc / secrets | `@hunt-misc` |
| Dispatch / chaining | `@hunt-dispatch` |
| Cloud IAM | `@cloud-iam-deep` |
| M365/Entra | `@m365-entra-attack` |
| Enterprise VPN | `@enterprise-vpn-attack` |
| Okta | `@okta-attack` |
| Meme coin audit | `@meme-coin-audit` |
| K8s | `@hunt-k8s` |
| Android APK | `@apk-redteam-pipeline` |
| OSINT | `@offensive-osint` |
| Supply chain | `@supply-chain-attack-recon` |

**For each finding:**
1. `validate_poc()` via MCP to verify PoC works
2. `log_finding()` via MCP to save to engagement DB
3. `track_test()` via MCP to log WSTG coverage
4. `create_exploitation_queue()` if further exploitation planned
5. Check `@hunt-dispatch` for chaining opportunities

**→ Transition:** *"Found something? → @validate to check reportability, then @report"*

---

### P5: CAPTURE — Evidence Hygiene

| Step | Action | What Happens |
|------|--------|--------------|
| 1 | Describe what you're about to screenshot | `@evidence-hygiene` loads |
| 2 | Redact cookies, PII, other users' data | Agent walks through redaction protocol |
| 3 | Capture evidence pack | Sanitized and organized |

---

### P6: VALIDATE — 7-Question Gate

| Step | Action | What Happens |
|------|--------|--------------|
| 1 | `@validate` or `@triage-validation` | Runs 7-Question Gate |
| 2 | Answer Q1–Q7 | Each must pass |
| 3 | Get verdict | **PASS** → report | **KILL** → discard | **DOWNGRADE** → lower severity | **CHAIN** → back to hunt |

**The 7 Questions:**
```
Q1: Can I demonstrate this RIGHT NOW with a real HTTP request?
Q2: Is the impact on the program's accepted list?
Q3: Is the vulnerable asset in scope?
Q4: Does it work without admin/privileged access?
Q5: Is this not already known/documented behavior?
Q6: Can impact be proved beyond "technically possible"?
Q7: Is this NOT on the never-submit list?
```

**Never-submit list:** missing headers, introspection alone, clickjacking alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, rate limits on non-critical forms, cookie flags alone.

**→ Transition:** PASS → *"Validated. → @report"* | KILL → *"Dead. Back to hunting."* | CHAIN → *"Back to P4."*

---

### P7: REPORT — Draft and Submit

| Step | Action | What Happens |
|------|--------|--------------|
| 1 | `@report` | Platform-appropriate reporter loads: `@report-writing` (H1/generic), `@bugcrowd-reporting` (Bugcrowd VRT), `@redteam-report-template` (client DOCX), `@redteam-mindset` (ops posture) |
| 2 | Provide endpoint, bug class, HTTP request/response | Template filled with CVSS |
| 3 | Review and copy-paste to platform | Submission-ready |

**Pre-flight:** `get_coverage()` and `generate_report()` via MCP.

**→ Transition:** *"Report drafted. Submit then loop back to hunt for more."*

---

## Autopilot Mode

```
@autopilot
```

Runs the entire P1–P7 pipeline **autonomously** — no prompts at each step. Only stops at the end to show you the report + PoC evidence for submission.

**What it does:**
1. Asks for target + platform + scope (once at the start)
2. Runs full recon via scripts (subdomain_enum, web_crawl, cariddi, nuclei, etc.)
3. Ranks attack surface (P1/P2/P3)
4. Tests every bug class with candidates using `@hunt-*` tradecraft
5. Logs findings, validates PoCs, tracks coverage
6. Generates final report
7. Presents report + evidence — you review and submit

**Checkpoint modes:** `@autopilot` runs fully autonomous. If you want step-by-step control, use the individual pipeline agents (`@scope` → `@recon` → `@surface` → `@hunt` → ...).

---

## Quick Hunt (Single Class)

```
@recon target.com --fast
@hunt-xss               (or whichever class)
@validate
@report
```

---

## Offensive Security & Red Teaming Capabilities

Dristi covers the full red-team kill chain — from perimeter recon through exploitation to client-facing deliverable.

### Recon & OSINT
| Agent | Capability |
|-------|-----------|
| `@offensive-osint` | Identity fabric mapping, breached credential lookup, email/phone/social enumeration, dark web intel, organizational footprint |
| `@osint-methodology` | 5-stage structured OSINT pipeline, source verification, persona tracking, geolocation |
| `@web2-recon` | Subdomain enumeration, technology fingerprinting, endpoint discovery, JS analysis, secret scanning |
| `@supply-chain-attack-recon` | Dependency confusion, package squatting, GH Actions dependency injection, SBOM mining |

### Enterprise Perimeter Exploitation
| Agent | Capability |
|-------|-----------|
| `@enterprise-vpn-attack` | Cisco ASA/FTD, Fortinet FortiGate, Citrix ADC/Gateway, Palo Alto PAN-OS, Pulse Secure, SonicWall, F5 Big-IP — CVEs and config weaknesses |
| `@m365-entra-attack` | AADSTS error analysis, Smart Lockout math, Conditional Access bypass, token theft, device registration abuse, ROPC, SAML SSO flow, hybrid identity |
| `@okta-attack` | Okta-as-IdP misconfig, SWA injection, delegated authentication flaws, API token abuse, event hook manipulation, push fatigue |
| `@cloud-iam-deep` | AWS IAM priv-esc (24+ patterns), Azure RBAC abuse, GCP IAM misconfig, cross-account role trust, IMDS, STS AssumeRole chaining |
| `@hunt-sharepoint` | SharePoint on-prem/online — ToolShell precondition chain, SOAP auth bypass, anon FormDigest, SafeControl enum |
| `@hunt-ntlm-info` | NTLM challenge capture, relay primitives, coercion, NetNTLMv2 interception, AD topology disclosure |

### Internal / AD / Cloud
| Agent | Capability |
|-------|-----------|
| `@hunt-k8s` | RBAC abuse, pod escape, secrets exposure, kubelet API, etcd access, admission controller bypass, container breakout |
| `@hunt-cicd` | GitHub Actions injection, GitLab CI abuse, Jenkins pipeline groovy, self-hosted runner compromise, artifact poisoning |
| `@hunt-ldap` | LDAP injection, anonymous binds, privilege escalation via LDAP, AD/LDAP misconfig |
| `@hunt-cloud-misconfig` | Open S3/Azure Blob/GCP buckets, public AMIs, unsecured databases, cloud metadata exposure |
| `@hunt-tls-network` | Weak cipher suites, outdated TLS versions, certificate validation bypass, STARTTLS injection |

### Mobile & Supply Chain
| Agent | Capability |
|-------|-----------|
| `@apk-redteam-pipeline` | APK acquisition (Play Store), jadx/apktool decompile, secret/JWT/Firebase grep, Frida instrumentation, cert pinning bypass, intent analysis |
| `@supply-chain-attack-recon` | Dependency confusion, package squatting, typosquatting, GH Actions injection, SBOM mining, registry poisoning |

### Web App Exploitation (48 `@hunt-*` agents)
Every OWASP-classified bug class: XSS (174 H1 reports), SQLi, SSRF (11 IP bypass techniques), IDOR, RCE (67 reports), SSTI (Jinja2/Twig/Freemarker/ERB/Spring), GraphQL, race conditions, deserialization (Java/PHP/.NET/pickle), HTTP smuggling (CL.TE/TE.CL/H2.CL), cache poisoning, JWT confusion, prototype pollution, XXE, WebSocket abuse, CORS, CSRF, file upload (10 bypass techniques), SAML (XSW1–XSW8), OAuth/OIDC, NoSQLi, ATO (9 paths), MFA bypass (7 patterns), business logic, source leak, Laravel/Spring Boot/Next.js/ASP.NET/Node.js framework abuse, and more.

### Post-Exploitation & Reporting
| Agent | Capability |
|-------|-----------|
| `@redteam-mindset` | Red-team operator discipline — primary directive, anti-patterns, burnout avoidance, engagement closure |
| `@evidence-hygiene` | Cookie/PII redaction, HAR sanitization, screenshot metadata stripping, chain of custody |
| `@redteam-report-template` | Client-facing DOCX deliverables — Subject / Observations / Impact / Recommendation / PoC, embedded screenshots |
| `@report-writing` | HackerOne/Bugcrowd/Intigriti/Immunefi templates, CVSS 3.1 scoring, remediation guidance |

**Autopilot mode:** `@autopilot` runs the full pipeline from recon through exploitation to report generation — fully autonomous, human reviews at the end.

---

## Master Checklist

```
[ ] P1: Scope — platform, in-scope, OOS, credentials registered
[ ] P2: Recon — subdomains, endpoints, secrets, classified
[ ] P3: Surface — P1/P2/P3 ranked + Kill List
[ ] P4: Hunt — relevant @hunt-* agents against findings
[ ] P4: Findings logged via log_finding()
[ ] P4: WSTG tests tracked via track_test()
[ ] P5: Evidence captured with hygiene
[ ] P6: Every finding validated via @validate
[ ] P7: Report drafted via @report
[ ] P7: Coverage checked via get_coverage()
[ ] P7: Report generated via generate_report()
```
