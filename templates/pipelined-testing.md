# Pipelined Vulnerability Discovery and Exploitation

## Overview

Phase 4 uses **independent pipelines** — each vulnerability class runs its own discovery→exploit pipeline in parallel with no synchronization barrier. When XSS analysis finishes, XSS exploitation starts immediately without waiting for SQLi or SSRF analysis to complete.

```
Pipeline 1 (XSS):      [Analysis] ──→ [Queue Validate] ──→ [Exploit]
Pipeline 2 (Injection): [Analysis] ──→ [Queue Validate] ──→ [Exploit]
Pipeline 3 (SSRF/etc):  [Analysis] ──→ [Queue Validate] ──→ [Exploit]
                        ↑ all start simultaneously, finish independently ↑
```

This eliminates the bottleneck where fast analysis agents wait for slow ones.

## Multi-Domain Pipeline Requirement

**CRITICAL**: Each pipeline MUST test endpoints across ALL in-scope domains with server-side processing, not just the primary domain.

**Before starting pipelines:**
1. Call `get_scope(engagement_id)` to list all in-scope domains
2. For each domain, determine if it has server-side input processing
3. Include endpoints from ALL server-side domains in the pipeline's endpoint list
4. Pipeline agents MUST receive endpoints grouped by domain: "Test /login on keycloak.example.com AND /auth/login?app_url= on api.example.com AND /search on app.example.com"

**A pipeline that only tests the primary domain and marks the test as "completed" is incomplete.** The test is completed only when all in-scope domains have been tested for that vulnerability class.

**Common mistake**: Primary domain is a static SPA → agent marks INPV-05 (SQLi) as N/A. But the auth provider has login forms and the API gateway has query parameters — both are SQLi-testable. The correct behavior: test SQLi on auth provider and API gateway endpoints, then mark as "completed" with notes covering all domains.

## Pipeline Agents (3 independent pipelines in parallel)

### Pipeline 1: XSS (Analysis → Exploit)
**WSTG Tests**: INPV-01 (Reflected), INPV-02 (Stored), CLNT-01 (DOM)
**Tools**: dalfox
**Deliverables**: `save_deliverable(eid, 'xss_analysis', report)` + `save_deliverable(eid, 'waf_intelligence', waf_report)`
**Queue**: `create_exploitation_queue(eid, 'xss', [...])`

**Analysis Phase:**
1. Read `templates/input-validation-guide.md` Section 4A
2. **Create TodoWrite items** for every input endpoint/parameter to test — each must be individually completed
3. For each endpoint, call `get_witness_payloads('html_body')` (or appropriate context) and inject the canary first
4. Test reflected XSS (canary → context-appropriate payloads → bypass testing)
5. Test stored XSS (forms, comments, profiles, file uploads)
6. Test DOM-based XSS (JavaScript sinks, postMessage, URL fragments)
7. Run `dalfox` against all input endpoints
8. Document WAF/filter behavior: what is blocked, what passes, encoding observations
9. Save analysis deliverable with: tested endpoints, findings, CSP/WAF observations, bypasses tried
10. Save WAF intelligence: `save_deliverable(eid, 'waf_intelligence', waf_report)` if WAF detected
11. Create exploitation queue with all confirmed/suspected vectors
12. `validate_exploitation_queue(eid, 'xss')` — address any FAIL results
13. **Verify TodoWrite shows 100% completion** before proceeding
14. Call `track_test()` for each WSTG test

**Exploitation Phase** (starts immediately after analysis):
1. Call `get_deliverable(eid, 'xss_analysis')` for context (CSP, WAF, filter behavior)
2. Call `get_deliverable(eid, 'waf_intelligence')` for WAF bypass intel (if exists)
3. Call `get_exploitation_queue(eid, 'xss')` to get pending entries
4. For each pending entry:
   - Use `get_witness_payloads(context)` to get context-appropriate payloads
   - Start with WAF-bypassing techniques from waf_intelligence
   - Attempt exploitation (cookie theft, session hijack, DOM manipulation)
   - Use Playwright MCP for DOM XSS proof if available
   - **Exhaustion gate**: Must try 3+ techniques, 5+ bypass variants before marking "failed"
   - Call `mark_exploited(eid, 'xss', vuln_id, result, evidence, techniques_attempted, bypass_attempts)`
5. Call `log_finding()` for each confirmed vulnerability

### Pipeline 2: Injection (SQLi + CMDi — Analysis → Exploit)
**WSTG Tests**: INPV-05 (SQLi), INPV-12 (CMDi)
**Tools**: sqlmap, commix, nosqli
**Deliverables**: `save_deliverable(eid, 'sqli_analysis', report)`
**Queues**: `create_exploitation_queue(eid, 'sqli', [...])` and `create_exploitation_queue(eid, 'cmdi', [...])`

**Analysis Phase:**
1. Read `templates/input-validation-guide.md` Sections 4B, 4C
2. **Create TodoWrite items** for every input endpoint/parameter
3. For each endpoint, call `get_witness_payloads('sql_string')` or `get_witness_payloads('command_shell')` and inject canary
4. Test SQL injection (error-based → boolean blind → time-based → UNION)
5. Test command injection (separators: `;`, `|`, `$()`, backticks → time-based blind)
6. Run `sqlmap` and `commix` against endpoints with input parameters
7. Document WAF/filter behavior and DB type indicators
8. Save analysis deliverable with: tested endpoints, error patterns, DB type, WAF behavior
9. Create exploitation queues for sqli and cmdi classes
10. `validate_exploitation_queue(eid, 'sqli')` and `validate_exploitation_queue(eid, 'cmdi')`
11. **Verify TodoWrite shows 100% completion**
12. Call `track_test()` for each WSTG test

**Exploitation Phase:**
1. Call `get_deliverable(eid, 'sqli_analysis')` for context (DB type, WAF behavior, error patterns)
2. Call `get_deliverable(eid, 'waf_intelligence')` if exists
3. For SQLi queue: attempt data extraction (table enum, credential dump, stacked queries)
   - Start with DB-specific techniques from analysis (PostgreSQL → `pg_sleep`, MySQL → `SLEEP`)
   - **Exhaustion gate**: 3+ techniques, 5+ bypass variants before "failed"
4. For CMDi queue: attempt command execution proof (`id`, `whoami`, `cat /etc/passwd`)
   - **Exhaustion gate**: 3+ separator types, 5+ bypass variants before "failed"
5. Call `mark_exploited()` and `log_finding()` for each

### Pipeline 3: SSRF + SSTI + Path Traversal (Analysis → Exploit)
**WSTG Tests**: INPV-18 (SSTI), INPV-19 (SSRF), INPV-04 (Path Traversal)
**Tools**: sstimap, ssrfmap, arjun
**Deliverables**: `save_deliverable(eid, 'ssrf_ssti_analysis', report)`
**Queues**: Three separate queues (ssrf, ssti, path_traversal)

**Analysis Phase:**
1. Read `templates/input-validation-guide.md` Sections 4D, 4E, 4F
2. **Create TodoWrite items** for every endpoint/parameter
3. Use context-aware payloads:
   - SSTI: `get_witness_payloads('ssti_template')` — inject `{{7*7}}` canary first
   - SSRF: `get_witness_payloads('ssrf_url')` — test internal URLs, metadata endpoints
   - Path traversal: `get_witness_payloads('path_traversal')` — test traversal sequences
4. Run `sstimap` and `ssrfmap`
5. Document filter/WAF behavior for each class
6. Save analysis deliverable
7. Create exploitation queues for each class
8. Validate all 3 queues
9. **Verify TodoWrite shows 100% completion**
10. Call `track_test()` for each WSTG test

**Exploitation Phase:**
1. Call `get_deliverable(eid, 'ssrf_ssti_analysis')` for context
2. Call `get_deliverable(eid, 'waf_intelligence')` if exists
3. For SSTI queue: safe RCE demonstration, config extraction
   - **Exhaustion gate**: 2+ template syntaxes, 3+ sandbox escapes before "failed"
4. For SSRF queue: internal network access, metadata endpoints, port scanning
   - **Exhaustion gate**: 3+ URL schemes/encodings, 5+ bypass variants before "failed"
5. For path traversal queue: file read proof (`/etc/passwd`, config files)
   - **Exhaustion gate**: 3+ traversal encodings, 5+ bypass variants before "failed"
6. Call `mark_exploited()` and `log_finding()` for each

## WAF/Defense Intelligence Deliverable

When ANY analysis agent detects WAF/filtering behavior, save a shared WAF intelligence deliverable that ALL exploitation agents will reference:

```
save_deliverable(eid, 'waf_intelligence', '''
# WAF/Defense Intelligence Report

## WAF Detection
- **Vendor**: Cloudflare / AWS WAF / ModSecurity / Custom / None detected
- **Detection method**: Response headers, block page content, timing patterns

## Blocked Patterns
- `<script>` tags → 403 response
- `' OR 1=1` → Connection reset
- `UNION SELECT` → Generic error page

## Successful Bypasses
- Time-based blind SQLi (`pg_sleep()`) → Not blocked
- Event handler XSS (`<img onerror=...>`) → Passes when tag is lowercase
- Double URL encoding → Bypasses path traversal filter

## Encoding Behavior
- URL encoding: Single decode (standard)
- HTML entities: Not decoded server-side
- Unicode normalization: Not observed

## Database Indicators
- Error syntax suggests PostgreSQL
- Connection string pattern: libpq

## Recommendations for Exploitation
- Prefer time-based techniques over UNION-based
- Use event handlers instead of script tags for XSS
- Double-encode path traversal sequences
''')
```

**First analysis agent to detect WAF** saves this deliverable. Subsequent agents append findings via `save_deliverable()` (overwrites with merged content). All exploitation agents read it before starting.

## TodoWrite Completion Gate

**MANDATORY for all pipeline agents.** TodoWrite is not optional tracking — it's a completion proof mechanism.

### Rules
1. **Before testing**: Create a TodoWrite item for EVERY input endpoint/parameter discovered
2. **During testing**: Mark each item `in_progress` when actively testing, `completed` when exhaustively tested
3. **Before saving deliverable**: ALL TodoWrite items must be `completed`
4. **Premature completion blocked**: An agent CANNOT save its deliverable or create its exploitation queue until TodoWrite shows 100% completion
5. **Skipped items**: If an endpoint is skipped (avoid rule, not applicable), mark completed with a note — but it must be explicitly addressed

### Example
```
TodoWrite items for XSS Analysis Agent:
1. [completed] Test /search?q= for reflected XSS (3 techniques, 5 bypasses tried)
2. [completed] Test /profile bio field for stored XSS (form + API, 4 payloads)
3. [completed] Test /api/comments body for stored XSS (JSON + multipart)
4. [completed] Test /redirect?url= for DOM XSS (JS sink analysis)
5. [completed] Test /error?msg= for reflected XSS (canary reflected, 2 payloads blocked by WAF)
→ 5/5 complete → agent may now save deliverable and create queue
```

## Exhaustion-Based Classification Gates

Exploitation agents MUST meet minimum effort thresholds before marking a vulnerability as "failed":

| Vuln Class | Min Techniques | Min Bypass Attempts | What Counts |
|------------|---------------|--------------------|----|
| XSS | 3 | 5 | Different payload types (reflected/stored/DOM), WAF bypass encodings |
| SQLi | 3 | 5 | Different techniques (error/boolean/time/UNION), DB-specific variants |
| CMDi | 3 | 5 | Different separators (;, \|, $(), `), encoding variants |
| SSTI | 2 | 3 | Different template syntaxes, sandbox escape attempts |
| SSRF | 3 | 5 | URL schemes, IP encodings, DNS rebinding variants |
| Path Traversal | 3 | 5 | Encoding variants (../, %2e%2e, double-encode) |

### Anti-Patterns (premature classification)
These are NOT valid reasons to mark "failed" without meeting exhaustion thresholds:
- "CSP blocks execution" → Did you try CSP bypass techniques? (nonce reuse, `base-uri`, unsafe-eval)
- "WAF blocks payload" → Did you try 5+ encoding/bypass variants?
- "Input is sanitized" → Did you check for context mismatches or post-sanitization concatenation?
- "Authentication required" → This is operational, not a security finding
- "Network error" → This is environmental, retry with different approach

### Valid "failed" Classification
A "failed" classification is valid ONLY when:
1. Minimum techniques and bypass attempts have been met
2. Each failed attempt is documented with evidence (request + response)
3. The defensive mechanism is identified as a specific security control (not just an error)
4. The `mark_exploited()` call includes `techniques_attempted` and `bypass_attempts` params

## Role-Based Pipeline Execution (Recommended)

For standard engagements, use **role-specialized templates** from `templates/agent-roles/` instead of the legacy combined prompt below. Each pipeline splits into two focused agents:

```
Analyzer (templates/agent-roles/analyzer.md, 75 max_turns):
  → Discovers vulnerabilities with canary/witness payloads
  → Saves analysis deliverable + exploitation queue
  → Calls validate_exploitation_queue()

[Orchestrator validation checkpoint]
  → Calls validate_exploitation_queue(eid, vuln_class)
  → If FAIL: re-spawns Analyzer with corrective prompt
  → If PASS: spawns Exploiter

Exploiter (templates/agent-roles/exploiter.md, 75 max_turns):
  → Reads analysis deliverable + exploitation queue via MCP tools
  → Loads WAF intelligence (if available)
  → Proves exploitation with escalating techniques
  → Calls mark_exploited() + log_finding() for each result
```

**Benefits over combined agent:**
- Better failure isolation: analysis survives if exploitation crashes
- Validation checkpoint between phases catches malformed queues
- More focused context per agent → higher quality output
- Same total turn budget (75+75 = 150)

**When to use the legacy combined template instead:**
- CTF challenges with <3 input endpoints
- Small single-page applications
- When `mode: ctf` is set in the engagement config

**Spawning procedure:**
1. Read `templates/agent-roles/analyzer.md`, fill `{eid}`, `{target_url}`, `{session_cookie}`, `{vuln_class}`, `{test_ids}`, `{endpoint_list}`, `{rules_output}`
2. Spawn Analyzer with `Task(prompt=..., subagent_type="general-purpose", max_turns=75)`
3. When Analyzer completes: call `validate_exploitation_queue(eid, vuln_class)`
4. Read `templates/agent-roles/exploiter.md`, fill `{eid}`, `{target_url}`, `{session_cookie}`, `{vuln_class}`, `{test_ids}`, `{rules_output}`
5. Spawn Exploiter with `Task(prompt=..., subagent_type="general-purpose", max_turns=75)`

See `templates/agent-roles/README.md` for the full role system documentation.

---

## Legacy Pipeline Prompt Template (Combined Agent)

Use this template for CTF challenges and small apps where splitting into Analyzer+Exploiter is unnecessary.

```
You are a PIPELINE agent performing vulnerability discovery AND exploitation on {target_url}
(engagement ID: {eid}). You run an independent pipeline: discover → validate → exploit.

## Your Assignment: {vuln_class}
WSTG Tests: {test_ids}
Endpoints to test: {endpoint_list}

## Credentials

## Rules
{rules_output}

## CRITICAL ANTI-LOOP RULES
1. If a curl request fails with DNS error, connection timeout, or network error: retry ONCE, then skip that endpoint and move to the next.
2. If authentication fails (401/403) on 3 consecutive requests: stop testing authenticated endpoints. Call track_test() for remaining tests with status='skipped' and note='Auth unavailable'. Return immediately.
3. If a tool (sqlmap, dalfox, etc.) hangs for >60 seconds: kill it, log as skipped, move on.
4. NEVER retry the same failing request more than 2 times total.
5. Before finishing: call track_test() for EVERY assigned test ID, even if skipped. An agent that returns without tracking all its tests is a failed agent.

## Honesty Framework (MANDATORY)
Read `templates/shared/honesty-framework.md` before starting. Key rules:
- **No exploit = no finding.** If you cannot demonstrate actual exploitation, classify as POTENTIAL, not EXPLOITED.
- **Never claim impact you didn't demonstrate.** "Payload reflected" ≠ "XSS confirmed".
- **Report what you actually saw**, not what you expected to see.

## Three-Tier Classification
Read `templates/shared/exploit-classification.md`. You MUST classify every exploitation result as:
- **EXPLOITED**: Full proof at L3+ (actual exploitation demonstrated)
- **POTENTIAL**: Evidence at L1-L2 (vulnerability exists but blocked by security control)
- **FALSE_POSITIVE**: Security control holds after exhaustive bypass (NOT a finding)

## Evidence Requirements
Before calling `log_finding()`, call `get_evidence_checklist('{vuln_class}')` and verify:
1. You have evidence at the required proof level
2. All mandatory checklist items are satisfied
3. Your evidence includes full request AND response
4. You have a reproducible curl command
Read `templates/shared/reproducibility.md` for the required evidence format.

## Mandatory Workflow

### Phase A: Analysis (discovery only)
1. Read `templates/input-validation-guide.md` for testing procedures
2. **Create TodoWrite items** for every endpoint/parameter you will test
3. Use `get_witness_payloads('{sink_context}')` for context-aware canary and payloads
4. Discover vulnerabilities using manual testing + CLI tools
5. Document WAF/filter behavior — if WAF detected, `save_deliverable('{eid}', 'waf_intelligence', report)`
6. Save analysis: `save_deliverable('{eid}', '{deliverable_type}', '<report>')`
   Include: tested endpoints, findings, filter/WAF behavior, bypass attempts, context observations
7. Create exploitation queue: `create_exploitation_queue('{eid}', '{vuln_class}', '<JSON array>')`
8. Validate queue: `validate_exploitation_queue('{eid}', '{vuln_class}')`
9. Track tests: `track_test()` for each WSTG test ID
10. **Verify ALL TodoWrite items are completed** before proceeding to Phase B

### Phase B: Exploitation (prove vulnerabilities)
1. Call `get_evidence_checklist('{vuln_class}')` to know what proof level is needed
2. Call `get_deliverable('{eid}', '{deliverable_type}')` to review your analysis context
3. Call `get_deliverable('{eid}', 'waf_intelligence')` for WAF bypass intel (if exists)
4. Call `get_exploitation_queue('{eid}', '{vuln_class}')` to get pending entries
5. For each pending entry:
   a. Use `get_witness_payloads(context)` for context-matched payloads
   b. Start with WAF-bypassing techniques from waf_intelligence
   c. Attempt exploitation — prove impact (data extraction, code execution, session theft)
   d. **Exhaustion gate**: Try {min_techniques}+ techniques, {min_bypasses}+ bypass variants before "failed" or "false_positive"
   e. **Classify using three-tier system**:
      - L3+ proof → `mark_exploited(... 'exploited' ...)`
      - L1-L2 evidence + blocked by security → `mark_exploited(... 'potential' ...)`
      - Security control holds after exhaustion → `mark_exploited(... 'false_positive' ...)`
      - No evidence of vulnerability → `mark_exploited(... 'failed' ...)`
   f. Call `mark_exploited('{eid}', '{vuln_class}', '<id>', '<result>', '<evidence>',
          techniques_attempted='<comma-separated list>', bypass_attempts=<count>)`
6. Call `log_finding()` for each EXPLOITED or POTENTIAL result with full evidence
7. **EXPLOITED findings**: Full severity based on actual impact
8. **POTENTIAL findings**: One severity level LOWER + "POTENTIAL" tag in title
9. **FALSE_POSITIVE**: Do NOT log as a finding — only recorded in exploitation queue
10. Include reproducible curl command in every finding's evidence

## Queue Entry Format
Each entry: {id, type, endpoint, parameter, evidence, payload_example, confidence, severity}
```

## Failure Isolation

- Each pipeline runs independently — if Pipeline 1 (XSS) fails, Pipelines 2 and 3 continue
- If analysis phase fails within a pipeline, the exploitation phase is skipped for that class
- If exploitation phase fails, findings from other pipelines are preserved
- Phase gate tracks which tests were completed regardless of pipeline success/failure

## Cross-Pipeline Review (after all pipelines complete)

After all 3 pipelines finish (or fail), the main agent performs:

1. **Read all deliverables**: `list_deliverables(eid)` and review analysis + WAF intel
2. **Cross-class chaining**: Look for combinations:
   - XSS + missing CSP → elevated severity
   - SSRF + internal services → chain to internal exploitation
   - SQLi + admin credentials → privilege escalation
   - Path traversal + config files → credential extraction → auth bypass
3. **Queue coverage check**: Ensure all exploitation queues have been processed
4. **MANDATORY: Call `phase_gate_check(eid, 4)`**

## Quality Gate Integration

- `phase_gate_check(eid, 4)` validates per-class completion after all pipelines finish
- Queues with 0 vulnerabilities are valid (class is clean)
- Core INPV tests (XSS, SQLi, CMDi, SSTI, SSRF, Path Traversal) must have track_test() entries
- Exhaustion warnings in mark_exploited() are logged but do not block — they inform the Final Judge
