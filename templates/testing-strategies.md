# Testing Strategies Reference

Read this file during testing phases for detailed strategy guidance.

## Per-Endpoint Test Matrix

After Phase 0 builds the endpoint map, you MUST create a test matrix to ensure systematic testing of every input endpoint against every applicable vulnerability class.

### How to Build the Matrix

At the end of Phase 0, construct this matrix and reference it throughout Phases 3-4:

**Rows**: Each endpoint with user input:
- Every form (with method, action, and each parameter name)
- Every API endpoint (with method and each parameter)
- Every URL with query parameters
- Every page that accepts user input via URL fragments or headers

**Columns**: Vulnerability classes to test:
1. **XSS** (WSTG-INPV-01/02) — test if input is reflected/stored
2. **SQLi** (WSTG-INPV-05) — test if input queries a database
3. **CMDi** (WSTG-INPV-12) — test if input is passed to system commands
4. **SSTI** (WSTG-INPV-18) — test if input is rendered by a template engine
5. **SSRF** (WSTG-INPV-19) — test if input fetches a URL server-side
6. **Path Traversal** (WSTG-INPV-04) — test if input is a file path
7. **IDOR** (WSTG-ATHZ-01/04) — test if input is an object reference
8. **CSRF** (WSTG-SESS-05) — test if state-changing request has CSRF protection

### Example Matrix

| Endpoint | Method | Params | XSS | SQLi | CMDi | SSTI | SSRF | PathTrav | IDOR | CSRF |
|----------|--------|--------|-----|------|------|------|------|----------|------|------|
| /search | GET | q | TEST | TEST | N/A | TEST | N/A | N/A | N/A | N/A |
| /login | POST | user, pass | TEST | TEST | N/A | N/A | N/A | N/A | N/A | TEST |
| /api/users/{id} | GET | id | N/A | TEST | N/A | N/A | N/A | N/A | TEST | N/A |
| /profile/edit | POST | name, bio | TEST | TEST | N/A | TEST | N/A | N/A | N/A | TEST |
| /upload | POST | file | N/A | N/A | TEST | N/A | N/A | TEST | N/A | TEST |
| /proxy | GET | url | N/A | N/A | N/A | N/A | TEST | N/A | N/A | N/A |

### Rules
- Mark each cell as: **TEST** (must test), **N/A** (not applicable with reason), or after testing: **SAFE**, **VULN** (finding logged)
- Every cell marked **TEST** must be tested before the phase is complete
- After Phase 4, present the completed matrix to the user as part of the coverage summary
- If an endpoint has >5 parameters, prioritize the most likely-injectable ones (search terms, IDs, filenames, URLs)

### How to Apply the Matrix
1. **Option A (by endpoint)**: For each row, test all applicable columns before moving to the next endpoint. Good for small applications (<10 endpoints).
2. **Option B (by vulnerability class)**: For each column, test all endpoints. Better for larger applications. Use parallel subagents per vulnerability class.
3. **Hybrid**: Test the highest-priority endpoints by-endpoint first, then sweep remaining endpoints by-vulnerability-class.

## Parallel Subagent Testing Strategy

Use the `Task` tool to spawn subagents for testing multiple endpoints or vulnerability classes simultaneously.

**When to parallelize:**
- **Phase 0 (Discovery)**: Spawn subagents to crawl different sections of the site simultaneously
- **Phase 2 (Config)**: Test security headers across multiple endpoints in parallel
- **Phase 4 (Input Validation)**: Test different vulnerability classes (XSS, SQLi, SSTI) on different endpoints simultaneously
- **Any phase with >5 endpoints**: Split endpoints across subagents

**How to parallelize:**
1. Divide the work into independent, non-overlapping chunks
2. Launch up to 3 Task subagents simultaneously, each with:
   - A specific list of endpoints to test
   - The specific WSTG test IDs to run
   - The engagement ID for logging findings
   - Session credentials/tokens for authenticated requests
3. Each subagent should use `log_finding` to record discoveries directly
4. After all subagents complete, review findings and check for chaining opportunities

**Example — parallel input validation testing:**
- Subagent 1: Test all form endpoints for XSS (WSTG-INPV-01, WSTG-INPV-02)
- Subagent 2: Test all form endpoints for SQL injection (WSTG-INPV-05)
- Subagent 3: Test all API endpoints for command injection and SSTI (WSTG-INPV-12, WSTG-INPV-18)

**Rules for parallel testing:**
- Never have two subagents test the same endpoint with the same payload (avoid duplicates)
- Each subagent must include session re-auth logic (sessions may expire independently)
- Rate-limit within each subagent — total request rate across all subagents should not overwhelm the target
- After parallel testing completes, do a sequential chaining review across all findings

## Vulnerability Chaining

After discovering a vulnerability, assess whether it can be used to escalate or discover additional vulnerabilities. Run this check after each finding is logged.

**Chain patterns to look for:**

1. **Information Disclosure → Targeted Attacks**
   - Leaked API keys/tokens → test them for valid access
   - Leaked internal paths → add to endpoint map and test
   - Leaked usernames/emails → use for authentication testing
   - Version numbers → search for known CVEs
   - Stack traces → identify exact framework version and config

2. **IDOR → Data Enumeration**
   - If you find an IDOR on `/api/users/1`, enumerate `/api/users/2`, `/api/users/3`, etc.
   - If IDOR exposes user data, extract emails/usernames for further auth testing
   - Use `ffuf` with sequential ID payload for bulk enumeration

3. **XSS → Session Hijacking / Privilege Escalation**
   - If stored XSS is found, note that it could steal admin session tokens
   - If reflected XSS bypasses CSP, note the elevated severity
   - Test if XSS can access sensitive API endpoints via JavaScript

4. **SQL Injection → Data Extraction**
   - If error-based SQLi is found, attempt to enumerate database tables
   - Extract credentials from the database
   - Check for stacked queries that could lead to RCE

5. **SSRF → Internal Network Scanning**
   - If SSRF is found, test access to internal services (169.254.169.254, localhost:port)
   - Check for cloud metadata endpoints
   - Attempt to reach internal admin panels

6. **Authentication Bypass → Escalation**
   - If you can bypass auth on one endpoint, test the same bypass on all protected endpoints
   - If default credentials work, test them on other admin interfaces

**Chaining workflow:**
1. After logging a finding, immediately check: "Can this finding help discover or exploit something else?"
2. If yes, perform the chained test before moving to the next WSTG test
3. Log each chained finding separately with a note referencing the original finding
4. Update the endpoint map if new endpoints or data were discovered

## WebSocket Testing

If the application uses WebSockets, test them during Phase 5 (Additional Testing).

**Detection — check for WebSockets during Phase 0:**
1. Look for `ws://` or `wss://` URLs in JavaScript files
2. Look for Socket.io, SignalR, or other real-time framework indicators
3. Check for `/socket.io/`, `/signalr/`, `/cable`, `/ws` endpoints

**Testing WebSocket connections:**
1. Use `websocat` or `wscat` (if available in Docker) to connect to WebSocket endpoints
2. Use `curl` to send the WebSocket upgrade handshake and test:
   - Cross-origin WebSocket requests (modify Origin header)
   - Missing authentication in WebSocket handshake
   - Message manipulation and injection
   ```bash
   ```

**What to look for:**
- Sensitive data in WebSocket messages (tokens, PII, credentials)
- No authentication required for WebSocket connection
- Server accepts WebSocket connections from any Origin
- Injection payloads in JSON message fields
- Rate limiting bypass via WebSocket (vs HTTP endpoint)

**Log findings from WebSocket testing under WSTG-CLNT (Client-Side) or WSTG-SESS (Session Management).**

## Saving Interesting Requests for Manual Review

When you find suspicious but unconfirmed behavior, save the request details to a file for the user to investigate manually.

**When to save requests:**
- Suspicious but unconfirmed findings
- Complex exploitation needing manual tweaking
- Authentication flows for the user to step through
- Edge cases with unusual server behavior

**How to save requests:**
```bash
```

**Naming convention in notes:**
- `[REVIEW] <description>` — needs human investigation
- `[CONFIRM] <description>` — Agent thinks it's vulnerable, needs manual confirmation
- `[BASELINE] <description>` — normal request for comparison

## Cross-Domain Test Matrix (MANDATORY for Multi-Domain Engagements)

**MANDATORY**: When the engagement involves multiple domains (e.g., app + auth provider + API gateway), you MUST build a separate test matrix per domain. This is not optional — it prevents the most common gap in multi-domain pentests: testing only the primary domain and marking everything else as N/A.

### App Domain (e.g., `app.example.com`)
Test all endpoints for standard vulnerability classes:
- XSS (reflected, stored, DOM-based)
- SQL Injection
- Command Injection
- SSTI / SSRF / Path Traversal
- CSRF on all state-changing endpoints
- IDOR on all endpoints with ID parameters
- **If static SPA**: Note "No server-side processing" but still test for: DOM XSS, clickjacking, open redirects, security headers, browser storage

### Auth Provider Domain (e.g., `auth.example.com`)
Test for OAuth/OIDC-specific vulnerabilities:
- `redirect_uri` manipulation and open redirect (WSTG-ATHZ-05 Step 2)
- `state` parameter validation (WSTG-ATHZ-05 Step 3)
- Token leakage via Referer headers (WSTG-ATHZ-05 Step 4)
- Authorization code replay (WSTG-ATHZ-05 Step 5)
- Scope escalation (WSTG-ATHZ-05 Step 6)
- PKCE bypass (for public clients)
- Alternative grant types (password, client_credentials, device_code)
- Admin console exposure (e.g., `/admin/`, `/realms/master/`)
- Well-known endpoint information disclosure
- **ALSO test standard INPV on login forms**: SQLi on username/password, XSS on error messages, SSTI on error pages

### API Gateway Domain (e.g., `api.example.com`)
Test all API-specific vulnerabilities — this is often the highest-value target in multi-domain setups:
- **All INPV tests** on every parameter that reaches the server (query params, path params, body params)
- Input validation on redirect/callback parameters (common SSRF/open redirect vectors)
- Rate limiting and abuse prevention
- Authentication bypass (accessing API endpoints without valid tokens)
- Cookie injection via unvalidated parameters
- Security headers (HSTS, CSP, X-Frame-Options)

### Cross-Domain Interactions
Test the boundaries between domains:
- Cookie scope misconfigurations (cookies scoped to parent domain leaking across subdomains)
- Token handling during redirect chain (tokens in URL parameters → Referer leakage)
- Mixed HTTP/HTTPS in the redirect chain
- CORS between app and auth provider domains
- Session confusion (app session valid on auth provider, or vice versa)
- JWT audience (`aud`) claim validation — can a token for one service be used on another?
- Logout propagation — does logging out of the app invalidate the IdP session?
- Session fixation via cross-domain cookie injection

### Subagent Split for Cross-Domain Testing

When using parallel subagents for cross-domain engagements:
- **Agent 1**: App domain — standard INPV tests (XSS, SQLi, CMDi) using cookie jar
- **Agent 2**: Auth provider domain — OAuth/OIDC-specific tests (WSTG-ATHZ-05)
- **Agent 3**: Cross-domain interactions — cookie scope, CORS, session handling

Each agent uses the shared cookie jar path: `-b ./engagements/<eid>/cookies.txt -c ./engagements/<eid>/cookies.txt`
