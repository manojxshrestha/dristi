# Dristi — Usage Guide

A practical guide to using the 85-agent Dristi bundle + WSTG MCP server for bug hunting (bounty programs, authorized pentesting, CTFs, vuln research) **and external red-team engagements** against enterprise targets. This document covers how the agents compose, and how to use them on a real engagement from intake through paid bounty (or final client deliverable).

> Built and validated through authorized red-team and bug-bounty engagements — exposed four bug-bounty capability gaps and five additional gaps around platform attack chains, mid-engagement IR detection, and client-facing reporting. The final stack documented here addresses both modes.

---

## 0. Brand new? Start here

This section is for people who have **never used the bundle before, never used OpenCode, or never done bug hunting**. If you're already comfortable with any of those, skim to Section 1.

### What is this bundle, in plain English?

It's a collection of 85 OpenCode agents + 86 MCP tools that turn OpenCode into a methodical bug-hunting assistant.

Without the bundle, asking the LLM *"is this XSS?"* gets you a generic answer. With the bundle installed, the same question loads the `hunt-xss` agent — which contains specific detection patterns from disclosed reports, the exact payloads that have worked, and a validation gate that prevents you from filing a false-positive bug report.

You don't "learn" the bundle. You install it once, then describe what you're testing in plain English, and the relevant agent auto-loads.

### What you DO need before starting

1. **OpenCode installed** — the CLI app, not a browser chat.
2. **A target you're authorized to test** — meaning either: (a) you own it, (b) it's on a bug bounty program's in-scope list, (c) you have a signed pentest engagement letter, or (d) it's a deliberately-vulnerable practice site (OWASP Juice Shop, Vulnweb, HackTheBox, etc.).
3. **The Dristi MCP server running** — see README.md for setup.
4. **Playwright browsers installed** — for client-side testing, screenshot capture, and auth flows. See [`docs/browser-flow.md`](browser-flow.md) for setup and usage. Quick install:
   ```bash
   npx playwright install chromium
   bash scripts/setup/ensure_browser.sh
   ```

### What you DON'T need

- ❌ You don't need to know how to write exploits. The agents include working payloads.
- ❌ You don't need to know Burp Suite. It's optional. Agents work with curl + browser.
- ❌ You don't need a bug bounty account yet. You can practice on OWASP Juice Shop first.
- ❌ You don't need to read all 85 agent files. They auto-load when relevant.

### Pick a practice target

If this is your first time, **do not point this at a real bug bounty program yet**. Practice on a deliberately-vulnerable site first.

| Target | URL | Why |
|---|---|---|
| **OWASP Juice Shop** | `docker run bkimminich/juice-shop` | Designed for learning, every OWASP Top 10 bug is in there |
| **Acunetix testphp** | http://testphp.vulnweb.com | Public, intentionally vulnerable, no signup |
| **HackerOne CTF (Hacker101)** | https://www.hacker101.com/ | Free CTF challenges, walkthroughs available |

### Walk through your first hunt on a practice target

```bash
# Start an engagement
cd /path/to/dristi
opencode
```

Then describe what you want to do:

> *I'm practicing on OWASP Juice Shop running on localhost:3000. This is a deliberately vulnerable training app, no authorization concerns. Walk me through finding my first bug — start with recon.*

**What happens next:**
- The `bb-methodology` agent loads (the 6-phase workflow)
- The agent walks you through Phase 1 (Scope) and asks: *"Is this practice mode?"*
- The `web2-recon` or `offensive-osint` agent loads and gives you concrete commands to run
- You follow along, paste results back, and the LLM spots vulnerable patterns

For example, when you find Juice Shop's `/api/users` endpoint with an `id` parameter, the `hunt-idor` agent loads and walks you through testing for Insecure Direct Object Reference.

### Common beginner mistakes (and how the bundle prevents them)

1. **Filing a report for "200 OK on /admin without auth"** — the path 200's but content is the login page. `triage-validation` Q6 requires concrete impact (actual admin data shown), not "technically possible."
2. **Testing on out-of-scope assets** — `triage-validation` Q3 explicitly asks scope.
3. **Submitting findings on the never-submit list** (missing security headers, clickjacking on non-sensitive pages, etc.) — `triage-validation` Q7 has the rejection list.
4. **Sharing screenshots with cookies/PII visible** — `evidence-hygiene` walks you through the redaction protocol BEFORE you take the screenshot.

---

## 1. Architecture overview

The stack maps to a 6-phase engagement workflow. Agents compose left-to-right through the workflow.

```
1 SCOPE  →  2 RECON  →  3 HUNT  →  4 VALIDATE  →  5 CAPTURE  →  6 REPORT
```

| Phase | What you're doing | Primary agents |
|---|---|---|
| **1. Scope** | Reading program rules, deciding what's in/out, scaffolding the engagement folder | `bug-bounty`, `bb-methodology`, `osint-methodology` |
| **2. Recon** | Asset discovery, subdomain enum, endpoint mapping, secret hunting | `offensive-osint`, `web2-recon`, `bb-local-toolkit`, `search-agent` |
| **3. Hunt** | Active testing for bugs in specific vuln classes | 48 `hunt-*` agents + 7 enterprise-platform agents + `security-arsenal` |
| **3.5. Deep-think** | (conditional) First-principles gap analysis when hunt yields zero | `deep-think` |
| **4. Exploit** | Deepen confirmed findings, attempt WAF bypass | 48 `hunt-*` agents + `web2-vuln-classes` |
| **4.5. Search-agent** | (conditional) 13-resource retrieval when exploit stalls | `search-agent` |
| **5. Validate** | Decide whether a lead is actually a reportable bug | `triage-validation` (7-Question Gate) via `/triage` or `/validate` |
| **6. Capture** | PoC screenshots, HAR files, evidence redaction | `evidence-hygiene` |
| **7. Report** | Draft and submit | `report-writing`, `bugcrowd-reporting` |

---

## 2. The discipline this stack enforces

Beyond the agents themselves, the stack enforces three habits that separate productive bug-bounty researchers from the noise:

1. **Validate before drafting.** `triage-validation`'s 7-Question Gate kills weak findings in 30 seconds. Submitting one well-validated P3 is better than three half-baked P4s, and dramatically better for your researcher reputation.

2. **Redact by default.** `evidence-hygiene` makes redaction the first step of evidence capture, not an afterthought. Every screenshot you take is reflexively cookie-safe and PII-safe.

3. **Specificity in reporting.** `bugcrowd-reporting`'s OOS rebuttal templates and severity-request paragraph turn a P4 default into a P3 outcome more often than not. Triagers respect specificity; they auto-close vagueness.

---

## 3. Worked example — full engagement walkthrough

### Step 1 — Program intake

Start OpenCode in the project directory and describe your target:

> *"Starting Dristi engagement on [target] — enterprise bug bounty program with web, API, mobile, and cloud in scope. Run scope intake with bb-methodology, register assets via MCP."*

The `bb-methodology` agent loads and walks through the program rules, identifying in-scope assets, OOS items, focus areas, and bounty bands. Use MCP's `register_scope()` to log domains.

### Step 2 — Recon

> *"Recon phase — subdomain enumeration, tech fingerprinting, JS secret scanning, S3 bucket discovery, and cloud asset mapping. Track results with MCP track_tool() and build the priority queue."*

The `offensive-osint` and `web2-recon` agents load with command suggestions (`subfinder`, `httpx`, `katana`, `gau`). Pasted output gets parsed and ranked via `prioritize_endpoints()`.

### Step 3 — Hunt across all vulnerability classes

As you encounter different attack surfaces, describe what you see. The matching `hunt-*` agent auto-loads:

| Attack surface | What to say | Agent loads | What it provides |
|---|---|---|---|
| **Search bar, form input, URL params** | *"XSS on the search field — testing reflected, stored, DOM, and blind contexts."* | `hunt-xss` | Context-specific payloads (html/attr/js/url), polyglots, WAF bypass, blind XSS callback templates |
| **URL parameter accepts http:// URL** | *"SSRF via the proxy parameter — trying cloud metadata, internal services, and blind OOB detection."* | `hunt-ssrf` | Cloud metadata URLs (AWS/Azure/GCP), internal CIDR probes, collaborator-based blind SSRF |
| **Login form, search, sort params** | *"SQLi on the login field — testing error-based, boolean blind, time-based, and stacked queries."* | `hunt-sqli` | Database-specific payloads, error extraction, time-based thresholds, WAF evasions |
| **Template parameter (name, content)** | *"SSTI on the template parameter — testing Jinja2, Twig, Freemarker, and Velocity payloads."* | `hunt-ssti` | Engine fingerprinting, RCE chains, sandbox escapes per template engine |
| **Command execution, ping, log params** | *"CMDI on the ping parameter — testing blind and out-of-band command injection."* | `hunt-rce` | Blind OOB payloads, time-based detection, filter bypasses |
| **API path with numeric ID** | *"IDOR in /api/users/{id} — testing cross-tenant access with two accounts."* | `hunt-idor` | Method swap, array wrap, parameter pollution, mass assignment, GraphQL node() enumeration |
| **Login, reset password, 2FA flow** | *"Auth bypass on the admin panel — testing path traversal, IP spoofing, and rate-limit gaps."* | `hunt-auth-bypass` | Path normalization, header injection, direct-access techniques, 2FA bypass patterns |
| **Session token, JWT, cookie** | *"ATO on the session handling — JWT alg confusion, session fixation, and 2FA bypass."* | `hunt-ato` | JWT manipulation (alg:none, RS→HS), session token analysis, MFA bypass chains |
| **GraphQL endpoint at /graphql** | *"GraphQL introspection and mutation analysis — testing for depth-limit bypass and batching."* | `hunt-graphql` | Introspection queries, field-suggestion enumeration, batch-attack rate limits |
| **File upload field** | *"File upload on /profile/avatar — testing RCE, XSS, and SSRF via upload."* | `hunt-file-upload` | Extension bypass, magic-byte tricks, polyglot payloads, content-type manipulation |
| **Race conditions on coupons/votes** | *"Race condition on the coupon endpoint — testing concurrent redemption."* | `hunt-race-condition` | Request timing, last-byte sync, Turbo Intruder scripts, TOCTOU patterns |
| **OAuth login button** | *"OAuth misconfiguration — CSRF + redirect_uri bypass + state validation."* | `hunt-oauth` | OAuth spec deviations, state nonce bypass, code injection, scope upgrade |
| **CORS header in response** | *"CORS misconfiguration — testing credentialed cross-origin reads."* | `hunt-cors` | Origin reflection, null bypass, preflight checks, wildcard with credentials |
| **XXE in XML upload/API** | *"XXE on the XML upload — testing out-of-band entity exfiltration."* | `hunt-xxe` | OOB DTD hosting, parameter entities, blind XXE, XInclude |
| **CSRF-protected form** | *"CSRF on the email-change endpoint — testing token validation and origin checks."* | `hunt-csrf` | Token analysis, origin/Referer validation gaps, same-site bypasses |
| **Prototype pollution in JS** | *"Prototype pollution in the JSON parser — testing client-side and server-side sinks."* | `hunt-prototype-pollution` | Sandbox escapes, property-injection chains, DevTools detection |
| **NoSQL/MongoDB in stack** | *"NoSQLi on the JSON login endpoint — testing operator injection."* | `hunt-nosqli` | MongoDB operator payloads, blind extraction, BSON injection |
| **LDAP in stack** | *"LDAP injection on the search endpoint — testing filter bypass."* | `hunt-ldap` | Filter injection, blind extraction, AD-specific queries |
| **Open redirect in URL param** | *"Open redirect in the ?next= parameter — testing for whitelist bypass."* | `hunt-open-redirect` | Protocol confusion, @-userinfo tricks, path-traversal in redirect |
| **HTTP/2 support** | *"H2C smuggling on the HTTP/2 endpoint — testing protocol downgrade."* | `hunt-h2clobber` | H2C smuggling, connection upgrade, backend confusion |
| **Deserialization in cookie/POST** | *"Deserialization in the session cookie — testing Java/Python/PHP gadget chains."* | `hunt-deserialization` | Language-specific gadget chains, ysoserial payloads, detection patterns |
| **Subdomain takeover CNAME** | *"Subdomain takeover — CNAME points to unclaimed cloud service."* | `hunt-subdomain-takeover` | Cloud provider takeover procedures, validation commands |
| **Email/spoofing/SPF** | *"Email security audit — SPF, DMARC, DKIM, and phishing feasibility."* | `hunt-email` | DNS record analysis, spoofing vectors, DMARC reporting |
| **Cloud IAM (AWS/Azure/GCP)** | *"Cloud IAM review — S3 bucket policies, IAM role chaining, privilege escalation paths."* | `cloud-iam-deep` | AWS/Azure/GCP IAM analysis, privilege escalation, misconfiguration scanning |
| **M365/Entra ID** | *"M365 tenant audit — Entra ID config, federation trust, app permissions, SharePoint enum."* | `m365-entra-attack` | Tenant fingerprint, federated domain risk, delegated permission abuse |
| **Android APK** | *"Android APK analysis — decompile, extract endpoints, hardcoded secrets, manifest review."* | `android-analysis` | APK decompilation, secret regex scanning, manifest permission analysis |
| **iOS IPA** | *"iOS app analysis — Mach-O binary, plist review, URL schemes, hardcoded tokens."* | `mobile-analysis` | Binary analysis, entitlement review, insecure data storage patterns |
| **Smart contract** | *"Smart contract audit — Solidity reentrancy, access control, oracle manipulation."* | `web3-audit` | Vulnerability patterns (reentrancy, flash loan, oracle, access control), gas optimizations |
| **Meme coin / token** | *"Token audit — honeypot detection, liquidity locks, ownership renounce, sell taxes."* | `meme-coin-audit` | Rug-pull patterns, authority retention, liquidity analysis, transfer restrictions |

### Step 4 — Validate before drafting

You think you have a finding. Before writing anything:

```
/triage
```

Or describe the finding to the LLM. The `triage-validation` agent runs the 7-Question Gate:

- Q1: Real HTTP request? Show me.
- Q2: Accepted impact per program?
- Q3: In scope?
- Q4: No admin-only assumption?
- Q5: Not already known / by design?
- Q6: Beyond "technically possible"? (Show actual victim data, not just 200 OK)
- Q7: Not on the never-submit list?

You get back **PASS**, **KILL**, **DOWNGRADE**, or **CHAIN REQUIRED**. If KILL — move on, don't draft.

### Step 5 — Capture evidence

> *"About to capture PoC screenshots for the finding. Walk me through redaction protocol."*

The `evidence-hygiene` agent loads. You get the cookie redaction protocol, PII black-bar rules, HAR sanitization filters, and the screenshot capture order.

### Step 6 — Draft and submit

```
/report
```

The `report-writing` agent loads (for the body template) and `bugcrowd-reporting` (for VRT mapping, severity request, OOS rebuttals if relevant). The output is a copy-paste-ready report.

### Step 7 — Track

Once submitted, use the MCP server to log the finding via `log_finding()` and append the UUID to your tracking. Use `track_test()` and `track_tool()` to maintain full coverage records.

---

## 4. MCP Server Integration

Dristi's WSTG MCP server provides 86 tools for methodology, tracking, and engagement management alongside the OpenCode agents.

### Typical workflow with MCP + agents

```
1. MCP: register_scope() → add domnains
2. Agent: offensive-osint loads, runs recon
3. MCP: track_tool() → log recon tool execution
4. Agent: hunt-idor or relevant hunt-* loads
5. MCP: log_finding() → save discovered vulnerability
6. Agent: triage-validation loads → run 7Q gate
7. MCP: track_test() → log WSTG test completion
8. MCP: get_coverage() → check test coverage
9. MCP: generate_report() → produce final report
```

---

## 5. Decision tree — which agent for which task

| Task / question | Agent(s) |
|---|---|
| "I want to start a new engagement" | Start OpenCode, describe target → `bb-methodology` loads |
| "How should I plan this hunt?" | `bb-methodology` + `osint-methodology` |
| "Find subdomains / endpoints / leaked secrets" | `offensive-osint` + `web2-recon` |
| "Which tool from my local stack does X?" | `bb-local-toolkit` |
| "I'm hunting [vuln class]" | `hunt-<class>` (auto-triggers on class mention) |
| "What's the payload that bypasses [filter]?" | `security-arsenal` |
| "Smart-contract audit for [protocol]" | `web3-audit` (or `meme-coin-audit` for tokens) |
| "I think I found a bug — should I report it?" | `/triage` (decides PASS / KILL / DOWNGRADE / CHAIN-REQUIRED) |
| "About to take a screenshot of my PoC" | Read `evidence-hygiene` first (cookie + PII redaction) |
| "Need to sanitize a HAR file before attaching" | `evidence-hygiene` (jq filter guidance) |
| "Drafting a report" | `/report` invokes `report-writing` (+ `bugcrowd-reporting` if Bugcrowd) |
| "Triager closed as OOS" | `bugcrowd-reporting` OOS rebuttal templates |
| "Triager downgraded my severity" | `bugcrowd-reporting` severity-request paragraph |

---

## 6. Limitations and known issues

- **`offensive-osint` is large**, even after refactor. The 15 reference files load on demand, but the SKILL.md still consumes context on every trigger.
- **Per-class `hunt-*` agents overlap on borderline classes.** A finding that's both IDOR and business-logic may trigger two agents. Manageable, but worth knowing.
- **Some `hunt-*` agents still rely on curl-only detection** — adding automated parameter fuzzing (arjun/x8) and request mutation to each is an ongoing effort. See [`docs/deep-testing.md`](deep-testing.md) for the manual workflow.
- **No HackerOne MCP yet.** Burp MCP works; H1 MCP integration is a future addition.
- **No engagement-coordinator agent.** Cross-finding tracking and submission ID management is currently manual. Future agent candidate.

---

## 7. Credits

See [docs/credits.md](credits.md) for full attribution.
