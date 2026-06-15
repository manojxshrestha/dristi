---
name: bb-methodology
description: Use at the START of any bug bounty hunting session, when switching targets, or when feeling lost about what to do next. Master orchestrator that combines the 12-phase pipeline (scope→auth→intel→recon→surface→hunt→deepthink→exploit→search→capture→validate→report) with the critical thinking framework (developer psychology, anomaly detection, What-If experiments). Routes to all other skills based on current hunting phase. Also use when asking "what should I do next" or "where am I in the process."
---

# Bug Bounty Methodology: 12-Phase Pipeline + Mindset

Master orchestrator for hunting sessions. Combines the 12-phase pipeline with the critical thinking framework that separates top 1% hunters from the rest.

---

## PART 0: MODE CONFIRMATION (Before Anything Else)

**Confirm the engagement type before deciding what counts as a finding.** The same target produces a different report shape depending on which mode applies. Getting this wrong is the single biggest waste of time in this workflow — answer it explicitly before Phase 1.

| Engagement type | What counts as a finding | What gets rejected |
|---|---|---|
| **Bug bounty** (H1 / Bugcrowd / Intigriti / private VDP) | Impact-demonstrated bugs ONLY. Full chain to attacker-attainable harm. | Hygiene (EoL software alone, permissive CSP alone, stack traces, info disclosure without concrete impact, "best practice" violations) |
| **Red team** (external client engagement) | Hygiene findings + recon + IoCs + defensive-state observations are ALL deliverables | Nothing — even "no finding here" is reportable as a positive defensive observation |
| **Pentest** (signed SoW / WAPT) | Depends on SoW. Read scope explicitly. Usually accepts hygiene + impact + recon | Out-of-scope assets, unsigned testing |
| **Internal audit** | Compliance-mapped findings (PCI / ISO / NIST / DPDPA / GDPR) | Findings without a control-mapping |

**Hard rule:** Before Phase 1 runs, write the engagement type as the first line in your hunt notes. If you can't answer it from the user's instruction, ASK once. Don't assume — the mistake costs both you and the triager.

**Lesson from an authorized engagement:** First-pass on this target produced 5 hygiene findings (SP2013 EoL, permissive CSP, stack traces) shipped in red-team format. The engagement was bug-bounty. Findings would have been N/A'd as "informational, no impact demonstrated." After the corrected pass with hygiene-as-context-not-finding, the same target yielded 11 impact-demonstrated bugs including 3 Critical.

---

## PART 1: MINDSET (How to Think)

### Core Principle

Hunting is not "find a bug" -- it is "prove an attack scenario." Think like an attacker with a specific goal, not a scanner looking for patterns.

### Daily Discipline: Define, Select, Execute

Before touching any tool:

1. **Define**: "Today I target [feature/domain] to achieve [CIA impact]"
2. **Select**: Choose 1-2 vuln classes (IDOR, Race Condition, etc.)
3. **Execute**: Focus ONLY on selected techniques. No wandering.

### 5 Ultimate Goals (Pick One Per Session)

1. **Confidentiality** -- steal data the attacker shouldn't see
2. **Integrity** -- modify data the attacker shouldn't change
3. **Availability** -- disrupt service (app-level DoS only)
4. **Account Takeover** -- control another user's account
5. **RCE** -- execute commands on the server

### 4 Thinking Domains

#### 1. Critical Thinking (deep analysis)

**Question trust boundaries:**
- Frontend control disabled? Send request directly via proxy
- `user_role=user` cookie? Change to `admin`
- `price=1000` in POST? Change to `1`
- `<script>` blocked? Try `<img onerror=...>`

**Reverse-engineer developer psychology:**
- Feature A has auth checks -> Similar feature B (newly added) probably doesn't
- Complex flows (coupon + points + refund) -> Edge cases have bugs
- `/api/v2/user` exists -> Does `/api/v1/user` still work with weaker auth?

**What-If experiments:**
- Skip checkout -> hit `/checkout/success` directly
- Skip 2FA -> navigate to `/dashboard`
- Send coupon request 10x simultaneously -> Race condition?
- Replace `guid=f8a2...` with `id=100` on sibling endpoint -> IDOR?

#### 2. Multi-Perspective (multiple angles)

| Perspective | What to check |
|------------|---------------|
| Horizontal (same role) | User A's token + User B's ID -> IDOR |
| Vertical (different role) | Regular user -> `/admin/deleteUser` |
| Data flow (proxy view) | Hidden params in JSON: `debug=false`, `discount_rate` |
| Time/State | Race conditions, post-delete session reuse |
| Client environment | Mobile UA -> legacy API with weaker auth |
| Business impact | "What's the $ damage if this breaks?" |

#### 3. Tactical Thinking (pattern detection)

- **Naming anomaly**: `userId` everywhere but suddenly `user_id` -> different dev, weaker security
- **Error diff**: Same 403 but different JSON structure -> different backend systems
- **Environment diff**: Prod vs Dev/Staging -> debug headers, CSP disabled
- **Version diff**: JS file before/after update -> new endpoints, removed params
- **Supply chain**: Check framework/library versions for known CVEs
- **Third-party integration**: Stripe/Auth0/Intercom -> webhook signature missing?

#### 4. Strategic Thinking (big picture)

- **Asymmetry**: Defender must patch ALL holes. You only need ONE.
- **Intuition engineering**: Log why something "feels wrong." Verify later. Update mental DB.
- **Unknown management**: Can't understand something? Add to "investigate later" list. Just-in-Time Learning.

### Amateur vs Pro: 7-Phase Comparison

| Phase | Amateur | Pro |
|-------|---------|-----|
| Recon | Main domain only | Shadow IT, dev environments, all assets |
| Discovery | Look for errors | Look for design contradictions, business logic flaws |
| Exploit | Give up when blocked | Build filter-bypass payloads |
| Escalation | Report the phenomenon only | Chain to real harm (session steal, ATO) |
| Feasibility | Include unrealistic conditions | Minimize attack prerequisites |
| Reporting | State facts only | Quantify business risk |
| Retest | Check if old PoC fails | Analyze fix method, find incomplete patches |

### Two Approach Routes

- **Route A (Feature-based)**: "This feature is complex" -> deep-dive its input handling -> find vuln
- **Route B (Vuln-based)**: "I want IDOR" -> find endpoints with sequential IDs -> test access control

### Anti-Patterns (Stop Doing These)

- **Program hopping**: Stick with one target minimum 2 weeks / 30 hours
- **Tool-only hunting**: Automation finds duplicates. Manual testing finds unique bugs.
- **Rabbit hole**: Max 45 min per parameter. Set a timer. If stuck, sleep on it.
- **No goal**: "Just looking around" = wasted time. Always Define first.

---

## PART 2: WORKFLOW (What to Do)

### The 12-Phase Pipeline (aligned with Dristi pipeline.md)

```
Phase 1:   SCOPE       → register domains, load config, create task tree
Phase 2:   AUTH        → test credentials, detect WAF, save auth deliverable
Phase 3:   INTEL       → passive OSINT: WHOIS, M365, cloud, spoof check
Phase 4:   RECON       → subdomain enum, crawl, params, nuclei, secrets
Phase 5:   SURFACE     → load recon, classify tiers + functional groups, prioritize endpoints
Phase 6:   HUNT        → test all bug classes via 54 hunt-* sub-agents
                        ├── group-based testing (1-2 reps per functional group)
                        ├── Ralph Wiggum loop: every endpoint must be covered before gate
                        └── (parallel) credential-attack → wordlist-gen → breach-check → osint-employees → spray
Phase 7:   DEEPTHINK  → (conditional) first-principles gap analysis when HUNT yields zero
Phase 8:   EXPLOIT     → deepen confirmed findings, escalate impact
                        ├── multi-auth-context probing (replay every finding with all sessions)
                        └── exhaustive exploitation gate (no finding skipped)
Phase 9:   SEARCH      → (conditional) 13-resource retrieval when EXPLOIT stalls
Phase 10:  CAPTURE     → evidence collection, screenshots, redaction
Phase 11:  VALIDATE    → re-validate PoCs, 7-Question Gate
Phase 12:  REPORT      → coverage check, generate final report
```

```mermaid
flowchart LR
    SCOPE --> AUTH --> INTEL --> RECON --> SURFACE --> HUNT --> DEEPTHINK --> EXPLOIT --> CAPTURE --> VALIDATE --> REPORT
    HUNT -->|"Ralph Wiggum: untested endpoints?"| HUNT
    EXPLOIT -->|"Exhaustive gate: un-exploited findings?"| EXPLOIT
    HUNT -.->|"zero findings"| DEEPTHINK
    EXPLOIT -.->|"WAF/CVE gaps"| SEARCH["SEARCH (research)"]
    SEARCH -->|"payloads found"| EXPLOIT
    VALIDATE -->|PASS| REPORT
    VALIDATE -->|KILL| DISCARD["Discard"]
    VALIDATE -->|DOWNGRADE| REPORT
    VALIDATE -->|CHAIN| HUNT
```

**THIS IS NOT LINEAR.** Move freely between phases. When stuck, return to a previous phase.

### Phase 1: SCOPE

**Goal:** Understand the target, define what's in/out, scaffold the engagement.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Ask user for target domain(s) and credentials | — |
| 2 | Parse scope table if provided | `parse_scope_table()` |
| 3 | Load engagement config | `load_engagement_config()` |
| 4 | Register all domains with types | `register_scope()` / `register_scope_batch()` |
| 5 | Create engagement in database | `findings_init()` |
| 6 | Create phase tracking tree | `create_task_tree()` |
| 7 | Gate check | `phase_gate_check(phase_completed=0)` |

**Output:** Registered engagement with scope boundaries, task tree created.

---

### Phase 2: AUTH

**Goal:** Obtain authentication credentials and detect WAF before testing.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Check for existing credentials | `get_engagement_config()` |
| 2 | Sign up or provide API key | — |
| 3 | Test auth works | `curl -sv <target>/api/me` |
| 4 | **WAF fingerprint check** | `identify_waf()` with response headers + body |
| 5 | If Cloudflare detected | Redirect 80% effort to API subdomain; use Playwright stealth for CF pages |
| 6 | Look up vendor fingerprints | `knowledge/waf/waf-knowledge-base/02-waf-fingerprints/<vendor>.md` |
| 7 | Save auth context with real tokens | `save_deliverable('auth_analysis', ...)` |

**WAF Detection:**
```bash
curl -sI https://<domain>/ 2>&1 | grep -i "server:\|cf-ray\|x-sucuri\|x-iinfo\|x-mod-security\|x-waf"
```
Pass headers + body through `identify_waf()` MCP tool. If identified, check vendor-specific fingerprints and known bypasses at `knowledge/waf/`.

**Route selection -- Wide or Deep?**

| Signal | Wide (recon sweep) | Deep (focused testing) |
|--------|-------------------|----------------------|
| New program, first day | X | |
| Wildcard scope `*.target.com` | X | |
| Main webapp, been here >3 days | | X |
| Scope update (new domain added) | X | |
| Found interesting subdomain | | X |

### Phase 3: INTEL (passive OSINT)

**Goal**: Passive intelligence gathering — WHOIS, cloud footprint, third-party exposure, email spoofability.

| Step | Action | Tool |
|------|--------|------|
| 1 | WHOIS lookup, M365/Azure tenant discovery | `whois`, `msftrecon` |
| 2 | Scope analysis from registered domain | `Scopify` |
| 3 | Third-party SaaS misconfiguration scan (Slack, Jira, GitHub, etc.) | `misconfig-mapper` |
| 4 | SPF/DMARC spoofability check | `Spoofy` |
| 5 | Cloud storage bucket enumeration (AWS S3, Azure Blob, GCP, DO Spaces) | `cloud_enum` |

**Script:** `scripts/tools/phase-intel.sh`

**Output:** Intel data to `runtime/engagements/<id>/recon/<domain>/intel/` — consumed by RECON for target context and by HUNT agents for WAF/cloud/third-party awareness.

### Phase 4: RECON

**Goal**: Discover attack surface — subdomains, endpoints, technologies, secrets.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Subdomain enumeration | `bash scripts/tools/subdomain_enum.sh <domain>` |
| 2 | Web crawling, parameter extraction | `track_tool()` |
| 3 | Cariddi, nuclei, directory bruteforce | `track_tool()` |
| 4 | 403 bypass, vhost fuzzing | `track_tool()` |
| 5 | Zone transfer, takeover scanner | `track_tool()` |
| 6 | Cloud recon, CVE scan, secrets discovery | `track_tool()` |
| 7 | Answer 3 triage questions per endpoint | — |
| 8 | Save endpoint map deliverable | `save_deliverable('endpoint_map_raw', ...)` |
| 9 | Gate check | `phase_gate_check(phase_completed=1)` |

**Wide approach** (initial sweep):
```
bash scripts/tools/subdomain_enum.sh <domain>
```

**Deep approach** (targeted):
```
Google Dorks -> JS file download -> Hidden param discovery -> API mapping
```

| What you find | Next action |
|--------------|-------------|
| Live subdomains with tech stack | Phase 5 (Surface) |
| Known software (WordPress, Jira) | Check CVEs + defaults immediately |
| Cloud resources (S3, Firebase) | Test permissions (read/write/list) |
| Nothing after 5 min on a host | Skip, try next host (5-minute rule) |

**Note**: `subdomain_enum.sh` runs subfinder + assetfinder + findomain → dnsx → httpx, outputting to `runtime/engagements/<id>/recon/<domain>/subdomains/`.

### Phase 5: SURFACE (Mapping & Analysis)

**Goal**: Convert raw recon output into a prioritized "test these first" list. Understand the app like its developer does.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Load endpoint_map_raw deliverable | `get_deliverable('endpoint_map_raw')` |
| 2 | Map all endpoints (Burp/Caido sitemap + JS analysis) | — |
| 3 | Identify auth model (cookie, JWT, OAuth, SAML?) | — |
| 4 | Find business-critical flows (payment, registration, password reset, data export) | — |
| 5 | Download and analyze JS files for hidden routes, secrets, logic | — |
| 6 | **Classify endpoints into functional groups** (auth, profile, api, admin, search, file, payment, infra) by path prefix — endpoints in the same group should be tested as a unit | — |
| 7 | Risk-score each endpoint | `prioritize_endpoints()` |
| 8 | Save ranked deliverable | `save_deliverable('endpoint_map_ranked', ...)` |
| 9 | Gate check | `phase_gate_check(phase_completed=2)` |

**Checklist:**
- [ ] Map all endpoints (Burp/Caido sitemap + JS analysis)
- [ ] Identify roles and permissions (user, admin, API keys)
- [ ] Note "weird" behaviors (anomalies in naming, errors, timing)

| What you find | Next action |
|--------------|-------------|
| JS files with interesting code | Taint analysis (Sink -> Source) |
| OAuth/SAML authentication | OAuth/SAML checklist |
| API with ID parameters | Phase 6 (Hunt), target IDOR |
| Complex business logic (payment, coupon) | Phase 6 (Hunt), target BizLogic |
| postMessage listeners | DOM analysis, postMessage-tracker |

### Phase 6: HUNT (Vulnerability Discovery — Unstructured)

**Goal**: Find the bug. Use Error-based first, then Blind-based.

**Decision flow based on what you're testing:**

```
What input are you testing?
+-- ID parameter (user_id, order_id)
|   -> IDOR checklist
+-- Search/filter/sort field
|   -> SQLi, NoSQLi probing
+-- URL input / webhook / PDF gen
|   -> SSRF checklist
+-- Text field reflected in page
|   -> XSS (DOM or reflected)
+-- File upload
|   -> SVG XSS, web shell, path traversal
+-- Price/quantity/coupon
|   -> Business logic, race conditions
+-- Login / 2FA / password reset
|   -> Auth bypass
+-- Profile update API
|   -> Mass Assignment
+-- Template / wiki editor
|   -> SSTI
+-- Nothing obvious
    -> Fuzz with ffuf, try Error-based probing
```

**Error vs Blind decision:**
1. Try Error-based first (send `'`, `"`, `{{7*7}}`, `${7*7}`) -- watch for 500 errors, stack traces
2. No error? Time-based (`SLEEP(10)`, `; sleep 10;`) -- watch response time
3. No time diff? OOB (`curl attacker.com`, interactsh) -- watch for DNS callback
4. Still nothing? Boolean (`AND 1=1` vs `AND 1=0`) -- watch content-length diff

| What you find | Next action |
|--------------|-------------|
| Low-impact behavior (redirect, self-XSS, cookie injection) | Chain it -- find a connector gadget |
| Confirmed vuln (XSS, IDOR, SQLi) | Phase 8 (Exploit) |
| Blocked by WAF/CSP/403 | Bypass techniques, then retry |
| Known software vuln (CVE) | 1-day speed workflow |
| Nothing after 20 min on this endpoint | Rotate (20-minute rule) |

### Phase 6b: STRUCTURED WSTG WALKTHROUGH (Full Coverage HUNT)

**Trigger:** User says `/full-hunt`, `/wstg`, "run full WSTG", "guided walkthrough", or "full coverage."

**Goal:** Walk through all 13 OWASP WSTG categories systematically, ensuring no vulnerability class is skipped. Each category loads the matching `hunt-*` agent, probes discovered endpoints, logs findings via MCP, and tracks coverage.

**How it works:**

1. Confirm mode + endpoints are already registered (SCOPE/RECON phases complete)
2. Walk through each category in WSTG order
3. Per category: load relevant agent → probe endpoints → `track_test()` per WSTG-ID → `log_finding()` per confirmed vuln
4. After each category: ask user "Continue? (y/skip/stop)"
5. After all 13: print summary, transition to VALIDATE phase

**Execution model:**

```
You: "/full-hunt"
LLM: Starting structured WSTG walkthrough — 13 categories, ~105 tests.

[1/13] INFO — probing endpoints...
[2/13] CONF — checking misconfigs...
[3/13] IDNT — analyzing identity flows...
...through [13/13] APIT...

Summary: 7 findings across 5 categories. Next: VALIDATE.
```

---

#### Category-by-category walkthrough

| # | Category | Tests | Agent(s) | What the LLM does per category |
|---|----------|-------|----------|-------------------------------|
| 1 | **INFO** — Information Gathering | 10 | `offensive-osint`, `osint-methodology` | Search engine recon, web fingerprint, directory enumeration, CMS detect, robot/`sitemap.xml` analysis, comment review, info leak check. Track each: `track_test("WSTG-INFO-01..10")`. Log discovered tech stack and hidden endpoints. |
| 2 | **CONF** — Configuration Management | 14 | `hunt-auth-bypass`, `security-arsenal` | Admin/management interfaces, debug endpoints (`/actuator`, `/.env`, `/phpinfo.php`), default credentials, HSTS/HTTPS config, CORS policy, file extensions, backup files. Check each discovered endpoint for common admin paths. Log misconfig findings. |
| 3 | **IDNT** — Identity Management | 5 | `hunt-ato` | Registration analysis (weak email verification, auto-confirmed), account enumeration (forgot password timing, status messages), role guessing (pre-defined roles admin/user/moderator), account provisioning. Log identity flaws. |
| 4 | **ATHN** — Authentication | 11 | `hunt-auth-bypass`, `hunt-ato` | Credential transport (HTTPS-only?), password policy, remember-me token, MFA/2FA bypass, password reset flow, account lockout, browser cache, CAPTCHA bypass, weak password change, re-auth sensitive features. Load both agents and walk ATHN checklist. |
| 5 | **ATHZ** — Authorization | 5 | `hunt-idor`, `hunt-cors` | IDOR in path/query params, RBAC/privilege escalation, CORS trust (Access-Control-Allow-Origin reflection), insecure direct object reference in POST body, GraphQL authorization gaps. Test each endpoint with crossed user sessions. |
| 6 | **SESS** — Session Management | 11 | `hunt-ato`, `hunt-csrf` | Cookie flags (HttpOnly, Secure, SameSite), JWT alg confusion (none, RS256, HS256), CSRF token validation, token origin verification, session fixation, secure cookie transmission, logout functionality, session timeout, CSRF in multi-step forms. |
| 7 | **INPV** — Input Validation | 20 | `hunt-xss`, `hunt-sqli`, `hunt-ssti`, `hunt-ssrf`, `hunt-xxe`, `hunt-ldap`, `hunt-nosqli`, `hunt-prototype-pollution`, `hunt-rce`, `hunt-file-upload`, `hunt-open-redirect`, `hunt-h2clobber`, `hunt-deserialization` | Heaviest category. For each endpoint discovered in RECON: probe all input params matching the appropriate handler. Search/query → XSS + SQLi. URL/webhook params → SSRF. Template fields → SSTI. XML endpoints → XXE. JSON endpoints → NoSQLi + prototype pollution. Upload → file upload RCE. Command params → CMDI. Cookies → deserialization. Headers → H2C smuggling. Load each `hunt-*` agent as its surface appears. |
| 8 | **ERRH** — Error Handling | 2 | `security-arsenal` | Error code review (malformed input → what status?), stack trace disclosure, debug error pages, custom error pages (info leakage). Probe discovered endpoints with malformed input. |
| 9 | **CRYP** — Cryptography | 4 | `security-arsenal` | TLS configuration (weak ciphers, SSLv3, TLS 1.0), padding oracle (CBC-MAC, POODLE), sensitive data in transit (password/token in clear), weak key generation, improper certificate validation. |
| 10 | **BUSL** — Business Logic | 10 | `hunt-race-condition`, `hunt-file-upload` | Workflow bypass (skip checkout → success page), payment manipulation (negative quantities, decimal shifts), coupon/reward abuse (race conditions, multiple redemption), feature misuse (free trial → permanent), state confusion, trust boundary violations, integrity check bypass. |
| 11 | **CLNT** — Client-Side | 14 | `hunt-xss`, `hunt-cors`, `hunt-prototype-pollution`, `security-arsenal` | DOM XSS (postMessage, hash fragment, URL params), CORS wildcard with credentials, clickjacking (X-Frame-Options/CSP frame-ancestors), HTML5 storage (localStorage secrets, sessionStorage tokens), cross-site scripting via CSS, client-side SQLi (WebSQL), self-XSS toward CSRF chain. |
| 12 | **APIT** — API Testing | 3 | `hunt-graphql` | GraphQL introspection ON → dump schema → discover hidden mutations, batch attack (rate-limit bypass via `[{query:...},{query:...}]`), REST verb tampering (GET→PUT→DELETE), SOAP XML injection, API auth bypass (no token → admin data?), rate limiting gaps. |
| 13 | **EXPLOITATION** — Chain & Escalate | - | All loaded `hunt-*` agents + `triage-validation` | Review all findings from phases 1-12. Identify chainable primitives: IDOR+CSRF→ATO, SSRF+cloud metadata→credentials, XSS+no CORS→session theft, open redirect+OAuth→token theft, SQLi+file write→RCE, race condition+business logic→$ abuse. For each chain candidate, load the appropriate agent and test. Only keep chains that pass the 7-Question Gate. |

---

**Before starting the walkthrough:**

1. Verify SCOPE + RECON phases are complete (registered domains, ranked endpoints)
2. If not, run them first or the walkthrough will miss surfaces to test
3. Print the endpoint inventory: "Testing against [X] endpoints: [list]"

**During the walkthrough:**

For each category, the LLM should:

```
1. Say: "[2/13] CONF — Configuration Management (14 tests)"
2. Load the relevant agent(s) → `hunt-auth-bypass` + `security-arsenal`
3. For each WSTG test in the category:
   a. Check if any discovered endpoint matches the test surface
   b. If yes: run probes, analyze responses
   c. If finding: `log_finding(engagement_id, title, severity, ...)`
   d. `track_test(engagement_id, "WSTG-CONF-XX", "completed", notes)`
4. After all tests: print category summary
5. Ask: "Category complete — X findings. Continue to [next category]? (y/skip/stop)"
```

**After the walkthrough completes:**

```
Walkthrough complete.

Summary:
  INFO     — 10 tests — 2 findings
  CONF     — 14 tests — 1 finding
  IDNT     — 5 tests  — 0 findings
  ATHN     — 11 tests — 1 finding
  ATHZ     — 5 tests  — 1 finding
  SESS     — 11 tests — 0 findings
  INPV     — 20 tests — 3 findings
  ERRH     — 2 tests  — 0 findings
  CRYP     — 4 tests  — 0 findings
  BUSL     — 10 tests — 1 finding
  CLNT     — 14 tests — 0 findings
  APIT     — 3 tests  — 1 finding
  EXPLOIT  — chains   — 2 chainable primitives

  Total: 11 findings across 7 categories.
  Coverage: get_coverage() to view full report.

Next phase: VALIDATE — run /triage on each finding.
```

**Per-test discipline rules apply:**
- Marker Discipline (unique 8+ char random strings)
- Body-Diff Rule (200 OK with identical body is NOT a bypass)
- Statistical-Sample Rule (n >= 10 interleaved for timing claims)
- Shell-Loop Ban (>5 iterations → use Python)

---

### Phase 7: DEEPTHINK (conditional — gap analysis)

**Goal**: First-principles gap analysis when HUNT yields zero findings or hits dead-ends.

If Phase 6 produces zero confirmed findings, switch modes:
- Re-read the endpoint map — look for surface you skipped
- Check WAF bypasses you haven't tried
- Research disclosed reports for similar tech stacks
- Load 3+ additional `hunt-*` skills relevant to observed tech stack

**Trigger:** Only when HUNT output is empty or blocked. See `.opencode/agents/deepthink.md`.

---

### Phase 8: EXPLOIT (Prove & Escalate)

**Goal**: Deepen confirmed findings — chain them, escalate impact, and attempt PoC exploitation.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Load all confirmed findings | `findings_list_vulns()` |
| 2 | Classify each finding to a vulnerability class (XSS, SQLi, SSRF, etc.) | `get_technique_guide()` |
| 3 | **Multi-auth-context probing:** Replay each finding with ALL available sessions (anonymous, user-1, user-2, admin) | `get_engagement_config()` |
| 4 | Attempt PoC exploitation with class-specific payloads | `validate_poc()` |
| 5 | If blocked — apply WAF bypasses | `get_waf_bypass()` |
| 6 | Run chaining analysis across findings | `find_chains()`, `findings_add_chain()` |
| 7 | **Exhaustive exploitation gate:** Every finding must have either a validated PoC or documented bypass exhaustion | `validate_poc()` |

**Escalation decision:**
```
What did you find?
+-- XSS
|   +-- Can steal cookie/token? -> Session hijack -> ATO
|   +-- Cookie is HttpOnly? -> Force email change via XHR -> ATO
|   +-- Self-XSS only? -> Find CSRF to trigger it
+-- IDOR
|   +-- Can read PII? -> Automate scraping, show scale
|   +-- Can change password/email? -> Direct ATO
|   +-- UUID only? -> Find UUID leak source, then retry
+-- SSRF
|   +-- DNS only? -> DON'T REPORT. Try cloud metadata
|   +-- Can reach 169.254.169.254? -> Extract keys -> RCE
|   +-- Internal port scan? -> Find Redis/K8s -> RCE
+-- SQLi
|   +-- Error-based? -> Extract data (passwords, tokens)
|   +-- Can INTO OUTFILE? -> Web shell -> RCE
|   +-- Blind? -> Boolean/Time extraction
+-- Open Redirect
|   +-- OAuth flow? -> Token theft -> ATO
|   +-- javascript: scheme? -> XSS
+-- Blocked by defense
|   -> Bypass (WAF/CSP/proxy/sanitizer/2FA)
+-- Low-impact, can't escalate alone
    -> Find connector gadget for chain
```

**Multi-auth-context probing:** For every confirmed finding, replay the exploit with ALL available auth contexts (anonymous, user-1, user-2, admin). A vulnerability that works in one session might not work in another — and a vulnerability that requires a specific privilege level is still reportable if the attacker can obtain that privilege. Auth-context rotation also surfaces session-isolation gaps where one user's token grants access to another user's data.

**After proving impact, check:**
- [ ] Can attack work with 0-1 clicks? (minimize prerequisites)
- [ ] Does it affect all users or specific role?
- [ ] What's the business $ impact?
- [ ] **Did you try this finding with ALL available sessions?** If not, run it through each auth context before moving on.

### Phase 9: SEARCH (conditional — research)

**Goal:** Research stale payloads, missing CVEs, and WAF bypass techniques when EXPLOIT stalls.

**Trigger:** Only when EXPLOIT hits a wall (WAF blocks, CVE payloads obsolete, technique unknown).

**Resources:**
- `websearch()` — current CVEs, disclosed reports, technique writeups
- `webfetch()` — PortSwigger, HackTricks, PayloadsAllTheThings
- `get_waf_bypass()` — vendor-specific bypass payloads
- `search_techniques()` — technique guide cross-reference
- `get_test_payloads()` — WSTG test payload repository
- HackerOne disclosed reports for similar tech stacks
- OWASP cheat sheets for current attack patterns

See `.opencode/agents/search.md`.

---

### Phase 10: CAPTURE (Evidence Collection)

**Goal**: Capture evidence with proper hygiene — redact cookies, PII, sanitize.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Load confirmed findings | `get_findings()` |
| 2 | Load evidence-hygiene for redaction protocol | `@evidence-hygiene` |
| 3 | For each finding: capture raw HTTP, screenshot (if DOM/visual), check collaborator (if OOB) | `validate_poc()` |
| 4 | **WAF evidence:** Capture blocked vs. bypassed request pairs, note evasion technique used | — |
| 5 | Apply redaction (cookies, PII, tokens) | — |
| 6 | Save sanitized evidence | `runtime/engagements/<eid>/recon/<domain>/evidence/<finding-id>/` |

---

### Phase 11: VALIDATE

**Goal**: Decide whether a finding is reportable before writing anything.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Load findings | `get_findings()` |
| 2 | Re-validate each PoC | `validate_poc()` |
| 3 | Cross-reference severity against MCP technique guides | `get_technique_guide()` |
| 4 | Run the 7-Question Gate | `@triage-validation` |
| 5 | Assign verdict | `update_finding()` |

**The 7-Question Gate:**
```
Q1: Can an attacker use this RIGHT NOW with a real HTTP request?
Q2: Is the impact on the program's accepted-impact list?
Q3: Is the vulnerable asset in scope?
Q4: Does it work without privileged access an attacker can't get?
Q5: Is this not already known or documented behavior?
Q6: Can impact be proved beyond "technically possible"?
Q7: Is this NOT on the never-submit list?
```

**Outcomes:**
- **PASS** — all 7 ✓ → proceed to Phase 12 (Report)
- **DOWNGRADE** — Q2 or Q5 fails → lower severity, still report
- **CHAIN REQUIRED** — needs another primitive → go back to Phase 6 (Hunt)
- **KILL** — any other failure → discard, do not draft

**Never-submit list:** Missing headers, introspection alone, clickjacking alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, rate limits on non-critical forms, cookie flags alone.

---

### Phase 12: REPORT

**Goal**: Generate a submission-ready report with coverage validation.

| Step | Action | MCP Tools |
|------|--------|-----------|
| 1 | Check WSTG coverage | `get_coverage()` |
| 2 | Check tool coverage | `get_tool_coverage()` |
| 3 | Final gate check | `phase_gate_check(phase_completed=5)` |
| 4 | Generate full report | `generate_report()` |
| 5 | Present report summary | — |
| 6 | Ask which platform (H1/Bugcrowd/Client) | — |

**Platform-specific reporters:**
- `@report-writing` — HackerOne/generic format
- `@bugcrowd-reporting` — Bugcrowd VRT mapping
- `@redteam-report-template` — Client-facing DOCX
- `@redteam-mindset` — Red-team ops posture

**Multi-Tool Reproduction Bar (Critical / High only):**

Before labeling a finding **Critical** or **High**, reproduce it via at least **two independent tools** (different stacks, different HTTP libraries). Cross-tool consistency rules out tool-artefact findings (e.g., a curl-only timing differential that disappears under Python `requests` was an artefact, not a bug).

Examples of independent reproductions:
- `curl` + Burp `send_http1_request` (different TLS stacks, different header normalisation)
- Python `requests` + raw socket via `ssl.wrap_socket` (one library normalises, one doesn't)
- Burp Repeater + Python `urllib` (same wire result expected from both)

The reproduction commands MUST be paste-into-shell ready in the report — a triager copies them verbatim. If the curl version requires special flags or breaks on certain systems, include a Python alternative.

**Lesson from an authorized engagement:** All three Critical findings (Authentication.asmx brute-force, TE.CL smuggling, NTLM Type-2 disclosure) were each independently reproduced via curl + Python raw sockets + Burp tooling. The cross-tool consistency was what convinced the triage write-up that the findings were not artefacts.

**Report:**
```
Run /report
+-- Platform-specific format (H1/Bugcrowd/Intigriti/Immunefi)
+-- Title: [Bug Class] in [Endpoint] allows [role] to [impact]
+-- Impact-first summary (sentence 1 = what attacker CAN do)
+-- Exact HTTP requests in Steps to Reproduce
+-- Under 600 words
+-- CVSS 3.1 score that MATCHES actual impact
```

**After submission:**
- [ ] While waiting for triage: try to escalate further (A->B signal method)
- [ ] If fix deployed: re-test for bypass (incomplete patch = new bug)
- [ ] Record finding with `/remember` for hunt memory

---

## PART 3: NAVIGATION & TIMING

### Non-Linear Navigation Quick Reference

| I'm stuck because... | Go to... |
|----------------------|----------|
| Can't find any subdomains | Phase 4: Run subdomain_enum.sh, try different recon sources |
| Found subdomain but don't know what to test | Phase 5: Map the app, download JS, classify functional groups |
| Testing but nothing works | Phase 6: Switch vuln class (20-min rotation rule) |
| Found a bug but impact is low | Phase 8: Escalation paths or gadget chaining |
| WAF/CSP/403 blocking my payload | Bypass techniques, then return to current phase |
| Been stuck for 45 min on one param | STOP. Rabbit hole. Move to next endpoint. |
| New API endpoint discovered during testing | Return to Phase 5: map it before attacking |
| Found one bug | A->B signal: same dev made more mistakes. Hunt 20 min for siblings. |

### 20-Minute Rotation Clock

Every 20 minutes ask yourself: **"Am I making progress?"**
- Yes -> Continue
- No -> Rotate to next: endpoint -> subdomain -> vuln class -> target
- Been on same target 2+ weeks with no findings? -> Consider switching program

### Pushback Protocol (When the User Says "Find More")

When the user disagrees with your stopping point — e.g., "I've found 10+ bugs, you should find the same," or "look harder," or "you're missing things":

**Default assumption: they are correct. You stopped early.**

Before pushing back with "I think we're done because X," do this:
1. **Re-read 3 more `hunt-*` skills** beyond what you have loaded. Pick ones that match observed surface (e.g., custom login → `hunt-auth-bypass`; SOAP endpoints → look for protocol-specific skills; URL parameters → `hunt-ssrf`).
2. **Re-attack the same surface** with the new skill checklists. Walk every step in the new skills, even if it feels redundant.
3. **Document negatives** as you go — a confirmed "no bug here" is itself a finding for the user to see (it proves coverage).
4. **Only after exhausting 3 new skills' checklists** do you push back, and only with a concrete list of what was tested.

**Lesson from an authorized engagement:** After a first-pass of 5 weak findings the user said "I have 10+, find them." Loading `hunt-auth-bypass` (which had been loaded but not walked through end-to-end) immediately surfaced the `/_vti_bin/Authentication.asmx` legacy SOAP login — the highest-impact bug in the engagement. The user was right; pushback would have been wrong.

### Tool Routing by Phase

| Phase | Tools | Why this order |
|-------|-------|----------------|
| Recon: Subdomains | `subdomain_enum.sh` (subfinder + assetfinder + findomain → dnsx → httpx) | Passive first (no detection) -> resolve DNS -> probe HTTP + tech stack |
| Recon: URLs | `gau` + `waymore` -> `katana` -> `uro` | Archive (forgotten endpoints) -> active crawl (JS-rendered) -> deduplicate |
| Recon: JS | `jsluice` + `mantra` + `trufflehog --only-verified` | Extract URLs/secrets -> find API keys -> verify keys actually work |
| Recon: Ports | `naabu` (wide) -> `rustscan` (deep) | Fast top-1000 sweep -> full 65535 on interesting targets |
| Recon: Scan | `nuclei -tags cve` -> `nuclei -tags takeover` | Known CVEs first -> then takeover (act immediately) |
| Mapping: Params | `arjun` + `paramspider` + ParamMiner | Brute-force hidden params + mine archives + cache headers |
| Mapping: JS code | Download -> `jsluice` -> VS Code/Cursor grep | Extract -> static analysis -> AI-assisted taint analysis |
| Mapping: Dorks | Manual Google Dorks | Custom per-target queries find what automation misses |
| Discovery: Fuzz | `ffuf -ac` + `cewl` custom wordlist | Auto-calibrate filtering + target-specific words beat generic lists |
| Discovery: XSS | `kxss` -> `dalfox` | Filter (which params reflect?) -> scan (only reflective params) |
| Discovery: SQLi | `ghauri` | Modern blind SQLi on ID-like parameters |
| Discovery: SSRF | `interactsh-client` | Self-hosted OOB listener for blind SSRF/XXE/RCE |
| Discovery: WAF | `wafw00f` -> `whatwaf` | Identify WAF vendor -> test bypass techniques |
| Exploit: 403 | `byp4xx` or `nomore403` | 20+ bypass techniques automated |
| Exploit: Takeover | `subzy` | Checks CNAME against 70+ vulnerable services |
| Exploit: Cloud | `s3scanner` + `aws` CLI | Scan bucket permissions -> extract metadata credentials |
| Exploit: Secrets | `trufflehog --only-verified` | Only verified working keys (no false positives) |

### Session End Checklist

- [ ] Save all Burp/Caido project files
- [ ] Record any "weird but not yet exploitable" behaviors (future gadgets)
- [ ] Update notes with failed attempts (don't re-test with same techniques)
- [ ] Log findings with `/remember`

---

## PART 4: METHODOLOGY DISCIPLINE (False-Positive Prevention)

Most retracted findings come from four recurring process bugs. Each has a hard rule.

> **Important framing:** These discipline rules are about *correctness of findings* — not throttling of effort. They tell you which signals are real findings and which aren't. They do **not** tell you to send fewer probes. If you find yourself using these rules to justify stopping early, you're misreading them — load `redteam-mindset` (DO NOT STOP primary directive) and continue. Coverage discipline and finding-correctness discipline are orthogonal axes; you need both on full.

### Marker Discipline

When testing for reflection, cache poisoning, parameter pollution, or OOB SSRF, the marker string you inject MUST be unique and unmistakable.

**Rules:**
- Markers are random alphanumeric strings, **8+ characters**, no English words, no protocol keywords.
- **NEVER** use `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`, `AAAA`, `BBBB`, your domain name, or any string that could plausibly appear naturally in the target's HTML/JS/error messages.
- **Good markers:** `cpmark987abc`, `x4hd2k9pq`, a Collaborator subdomain prefix like `dlsrcurl.<collab>.oastify.com`, or `__ZZ_MARKER_<random>_ZZ__`.
- Before claiming reflection: search the **baseline** (no-marker) response for the marker string. If it appears naturally, change your marker. This single check catches 80% of false-positive reflection reports.
- For OOB testing, sub-tag each Collaborator payload (e.g., `dlsrcurl.<collab>`, `authsrc.<collab>`) so callbacks identify the specific sink that fired.

**Lesson from an authorized engagement:** Initial scan flagged `X-Forwarded-Proto: javascript` as reflecting into multiple SharePoint pages. The "reflection" was the literal word `javascript` appearing naturally in SP help-link hrefs (`href="javascript:HelpWindowKey(...)"`). False positive caused by a non-unique marker.

### Body-Diff Rule

A bypass claim requires response **body** differential, not just status code.

**Rules:**
- 200 OK with byte-identical body to the baseline is NOT a bypass.
- 200 OK with a 5-byte difference might be — verify what changed (correlation ID? timestamp? real content?).
- Always diff the body side-by-side before claiming bypass: `diff <(curl ... baseline) <(curl ... bypass)`.
- Status-code-only claims (e.g. "Host header X gave 200 instead of 403") are the most common rejected-as-N/A category on bug bounty platforms.

**Lesson from an authorized engagement:** `Host: target.example:80@evil.example.com` returned HTTP 200 instead of the baseline 403. Looked like a Host-header bypass. But the body was byte-identical (8341 bytes both) — the AWS ELB normalised the Host to `target.example:80`, dropping the `@evil` portion. Not a bypass.

### Statistical-Sample Rule (for timing-based claims)

Single outliers are NOT signal. Network jitter routinely produces 2× outliers.

**Rules for any user-enum / blind-SQLi / blind-NoSQLi / timing-side-channel claim:**
- Minimum sample size: **n ≥ 10 INTERLEAVED trials per group** (control + test, randomised order, not back-to-back).
- Compute mean, median, σ for each group.
- A signal requires the suspect group's mean to be **≥ 2σ above** the control group's mean.
- A single 2× outlier in n=1 testing is jitter, not signal.

**Lesson from an authorized engagement:** Single-shot probe showed `Administrator` taking 1527 ms vs ~700 ms control on Authentication.asmx Login — looked like clear user-enum signal. Reproduction with n=80 interleaved trials across 8 groups collapsed every group to mean=685-716 ms, σ=25-74 ms. The 1527 ms was network jitter. Finding retracted.

### Shell-Loop Ban (>5 iterations)

For any iteration that runs more than 5 times, **use Python (with try/except per iteration), not shell for-loops.**

**Why:** zsh array expansion fails silently on edge cases. A loop like `for x in "${arr[@]}"` can produce zero iterations with no error if the array wasn't populated by the previous command. The user sees output that looks complete but actually skipped the test entirely.

**Rules:**
- Loops of ≤5 hardcoded items in shell: OK.
- Anything that iterates a list, file, or computed range: Python.
- Always count results. If you expected 100 probes and got <50 lines of output, your loop ate something.

**Lesson from an authorized engagement:** A zsh array-iteration verb-tampering test silently produced no curl invocations across 20+ iterations (zsh ate the array). Output looked like "HIT [GET] /_api/web → " repeated for every probe but the actual response was missing. ~50 probes worth of testing lost. Switching the test to Python with explicit per-iteration logging surfaced the real results.

---

## Related Skills & Chains

- **`hunt-dispatch`** — When PART 0 mode is confirmed (redteam / wapt + blackbox|greybox). Workflow primitive: after the engagement-type answer is locked, hand off to `hunt-dispatch` to fingerprint the target and load the matching platform + hunt-* skill set; this skill stops being the active context once dispatch prints its taxonomy.
- **`bug-bounty`** — When the user asks a generic "what should I do" or starts a new target. Workflow primitive: `bug-bounty` is the orchestrator that names which `hunt-*` skills to load by topic; this skill (`bb-methodology`) provides the 12-phase pipeline that orchestrator runs against.
- **`triage-validation`** — When a finding completes Phase 8 (Exploit) and is about to be written up. Workflow primitive: Phase 11 (Validate) explicitly calls `/validate` (the 7-Question Gate); only findings that pass all 7 questions get handed off to `report-writing`.
- **`offensive-osint`** + **`web2-recon`** — When Phase 4 (Recon) is active. Workflow primitive: Phase 4's "Wide approach" delegates to `offensive-osint` for asset arsenal and `web2-recon` for the live-host + URL pipeline.

---

## Operator Notes

> Engagement-derived additions to the vendored foundation. Wisdom from real
> authorized engagements + Phase 2 verification across this repo's 31+
> skill-area live tests. The upstream methodology covers the WHAT; this
> layer covers the WHEN-IT-ACTUALLY-WORKS and the FAILURE-MODES.

### What the methodology doesn't tell you

The vendored 12-phase workflow is a checklist; real engagements are improvisation. Sometimes you skip phases entirely — a client hands you a single URL and a JWT, recon was already done by their internal team, and Phase 4 collapses to a 10-minute fingerprint. Sometimes you spend 80% of the engagement in Phase 4 because the scope is a 200-asset financial-services parent org and asset discovery IS the work. The methodology is a map of terrain that exists in every engagement, not a sequence you traverse uniformly.

### Mode-confirmation, in practice

PART 0 (the bug-bounty vs WAPT vs red-team gate at the top of this file) is a hard rule, but the answer isn't always handed to you. Read the scope language:

- **"in-scope assets"** + **"out-of-scope assets"** + **"safe harbor"** → bug-bounty discipline. Validation-heavy, OOB-required, no exfil.
- **"kill chain"** + **"objectives"** + **"flag capture"** + **"adversary emulation"** → red-team. Stealth, persistence, lateral movement valid.
- **"compliance"** + **"PCI"** + **"HIPAA"** + **"executive report"** + **"remediation timeline"** → WAPT. Coverage-driven, deliverable-focused, all findings count regardless of exploitability.

When the language is mixed (common — clients often write WAPT-shaped SOWs and call them red-team engagements), default to bug-bounty discipline until proven otherwise. It's the most validation-strict mode; you can always relax later if the client confirms red-team. The reverse — assuming red-team latitude on what turns out to be a WAPT — gets findings retracted at delivery.

### Phase priority shifts by target type

The 12 phases are not equal-weight. Engagement type dictates the time allocation:

| Engagement | Recon | Hunt | Validate+Report |
|---|---|---|---|
| SaaS bug-bounty (defined scope) | 10% | 70% | 20% |
| External red-team (wide scope) | 40% | 30% | 30% |
| WAPT (asset list provided) | 0% | 60% | 40% |
| Enterprise on-prem (single product) | 5% | 50% | 45% |

If you find yourself spending 50% of a SaaS bug-bounty engagement in recon, you're procrastinating on the hunt. If you're spending 10% of an external red-team engagement on recon, you've already lost — the attack surface map IS the deliverable on those.

### When to break the methodology

If you find a Critical in the first 30 minutes of recon, **stop reconning, validate the Critical fully, report it, then return to recon.** The methodology says "complete the phase before moving on" — the value-per-hour curve disagrees. A confirmed Critical paying out within 24h of engagement start is worth more than a comprehensive asset list you'll never get to chain.

The same applies in reverse: if you've been hunting a candidate for 4+ hours and it won't reproduce on a second account, the candidate is dead. Don't sink another 4 hours into making a dead candidate reproduce. Drop it, document the retraction in your notes, move on.

### The discipline rules are non-negotiable

The discipline rules in this file — OOB Gate, Marker Discipline, Body-Diff Rule, Statistical-Sample Rule, Server-Policy-vs-State, Pre-Severity Gate, Shell-Loop Ban — are not methodology. They are quality gates. Methodology is the order of operations; these are the validation guarantees at each step.

Verified across Phase 2D's hardened-lab campaign: 8/8 discipline rules fired correctly against fake-bug-shaped behavior (URL echo dressed as XSS, word collision dressed as reflection, status-code-only "bypasses" with byte-identical bodies, 200-OK leak-claims with no actual leak data). Validation rates fall sharply when these rules get skipped. The friction is the feature — if a rule feels obstructive, that's it doing its job. The findings it kills are the half that would have come back N/A anyway.
- **`evidence-hygiene`** — When Phase 10 is collecting PoC screenshots / HARs. Workflow primitive: before any cookie / PII appears in a screenshot, hand off to `evidence-hygiene` for the redaction protocol.
