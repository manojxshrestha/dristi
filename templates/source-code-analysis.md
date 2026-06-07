# Source Code Analysis Template

You are performing a security-focused source code review of the target application's repository. Your analysis will inform all subsequent testing phases — every vulnerability agent and exploitation agent will reference your findings.

## Objective

Generate a comprehensive security architecture summary with critical file paths, attack surface mapping, and vulnerability indicators. Focus on **security-relevant components only** — skip documentation, tests, and non-security code.

## Analysis Strategy

Use 3 Task subagents in parallel for Phase 1 (Discovery), then 3 more for Phase 2 (Backward Taint Analysis).

**Agent Role Mapping**: Phase 1 discovery agents (Agents 1-3) use the **Scout** role (`templates/agent-roles/scout.md`) — they map architecture, entry points, and security patterns without analyzing vulnerabilities. Phase 2 taint analysis agents (Agents 4-6) use the **Analyzer** role (`templates/agent-roles/analyzer.md`) — they identify potential sinks and trace taint chains.

### Phase 1: Discovery (3 parallel agents — Scout role)

**Agent 1 — Architecture Scanner:**
- Identify the technology stack (framework, language, database, auth library)
- Map the application structure (MVC, microservices, monolith)
- Identify middleware, interceptors, and request pipeline
- Document configuration files and environment variables

**Agent 2 — Entry Point Mapper:**
- Find all HTTP route definitions (controllers, handlers, API endpoints)
- Map URL patterns to handler functions
- Identify parameter types (query, body, path, header)
- Catalog file upload endpoints and multipart handling
- Find WebSocket, GraphQL, and SSE endpoints

**Agent 3 — Security Pattern Hunter:**
- Identify authentication mechanisms (JWT, session, OAuth, SAML)
- Map authorization checks (RBAC, ABAC, middleware guards)
- Find input validation and sanitization functions
- Identify rate limiting, CSRF protection, CORS configuration
- Document WAF rules, security headers, CSP policies

### Phase 2: Backward Taint Analysis (3 parallel agents — Analyzer role)

**CRITICAL METHODOLOGY: Work BACKWARD from dangerous sinks to user-controlled sources.** Do not trace forward from inputs. Start at the sink, trace the variable backward through assignments, function calls, and transformations until you reach a user-controlled source (or confirm the data is safe).

**Agent 4 — Output Sink Backward Tracer (XSS/Injection):**

Start from dangerous OUTPUT sinks and trace BACKWARD to find user-controlled inputs:

1. **Find all output sinks** (search for these patterns):
   - HTML rendering: `innerHTML`, `document.write()`, `v-html`, `dangerouslySetInnerHTML`, triple-braces `{{{...}}}`, `| safe`, `mark_safe()`, `raw()`, `<%- %>`
   - SQL queries: raw query construction, string concatenation in queries, `$where`, `.extra()`, `.raw()`, `sequelize.query()`, `knex.raw()`, template literals in SQL
   - Command execution: `exec()`, `system()`, `popen()`, `spawn()`, `subprocess.run()`, backticks, `child_process`, `os.system()`
   - Template rendering: `render_template_string()`, `Template()`, Jinja2 with `| safe`, Twig `raw`, Freemarker `?no_esc`
   - Deserialization: `pickle.loads()`, `unserialize()`, `readObject()`, `yaml.load()` (without SafeLoader), `JSON.parse()` of untrusted data into eval

2. **For each sink, trace backward**:
   - Identify the variable that reaches the sink
   - Trace it backward through assignments, function calls, transformations
   - At each step, record file:line
   - Determine if the variable originates from user input (request params, headers, cookies, DB data from user, file uploads)
   - Note ALL sanitization/encoding on the path (name, type, file:line)

3. **Check sanitization context-appropriateness**:
   - SQL sinks: Only parameterized queries / prepared statements are safe. String escaping is NOT safe. Type casting is safe for numeric slots only.
   - HTML sinks: HTML entity encoding for HTML body context. JavaScript escaping for JS string context. URL encoding for URL context. **Context mismatch = vulnerable.**
   - Command sinks: Only array-based execution (shell=False) or `shlex.quote()` is safe. Regex blacklists are NOT safe.
   - Template sinks: Sandboxed context + autoescape is safe. User input in template expressions is NEVER safe.

4. **Flag post-sanitization concatenation**: If sanitization is applied but the data is later concatenated with unsanitized input or re-processed, the sanitization is nullified. This is a critical finding.

5. **Classify each taint chain**:
   - **VULNERABLE**: Tainted input reaches sink with no defense or wrong defense
   - **SAFE**: Proper context-appropriate sanitization on all paths
   - **NEEDS TESTING**: Sanitization present but bypass potential exists (e.g., blacklist-based)

**Agent 5 — Network/File Sink Backward Tracer (SSRF/Path Traversal):**

Start from dangerous NETWORK and FILE sinks and trace backward:

1. **Find all network sinks**:
   - HTTP clients: `fetch()`, `axios.get/post()`, `requests.get()`, `urllib.urlopen()`, `http.get()`, `HttpClient`, `WebClient`
   - DNS: `dns.lookup()`, `getaddrinfo()`
   - Redirects: `res.redirect()`, `302 Location`, `window.location`, `header('Location: ...')`
   - WebSocket: `new WebSocket(url)`, socket connections

2. **Find all file system sinks**:
   - File reads: `fs.readFile()`, `open()`, `File.read()`, `include()`, `require()`, `file_get_contents()`
   - File writes: `fs.writeFile()`, `open(..., 'w')`, `move_uploaded_file()`
   - Path construction: `path.join()`, string concatenation with paths, `os.path.join()`

3. **For each sink, trace backward** (same methodology as Agent 4)

4. **Check for validation**:
   - SSRF: URL scheme allowlist? IP allowlist/blocklist? DNS resolution check? Can it be bypassed (DNS rebinding, encoding, IPv6, decimal IP, redirects)?
   - Path traversal: Path canonicalization? Chroot/jail? Allowlist of directories? Can traversal sequences (`../`, `..%2f`, `....//`) bypass validation?
   - Redirect: Open redirect checks? Allowlist of destinations?

5. **Classify each taint chain** (VULNERABLE / SAFE / NEEDS TESTING)

**Agent 6 — Data Security & Auth Flow Auditor:**

1. **Backward trace credential flows**:
   - Find where passwords are stored → trace backward to see if they're hashed before storage
   - Find where tokens are generated → trace backward to see entropy source
   - Find where sessions are created → trace backward to see what data is included

2. **Standard data security audit**:
   - Find credential storage and handling (hashing algorithm, salt, iterations)
   - Identify sensitive data in logs, error messages, responses
   - Map data flow between components (trust boundaries)
   - Find hardcoded secrets, API keys, tokens
   - Identify insecure defaults and misconfigurations

## Required Output Sections

### 1. Executive Summary
Brief overview of the security posture (2-3 paragraphs).

### 2. Architecture & Technology Stack
- Framework and version
- Database type and ORM
- Authentication library
- Frontend framework
- Security implications of each technology choice

### 3. Authentication & Authorization Deep Dive
- Login flow (step by step with file paths)
- Session management mechanism
- Token generation and validation
- Role/permission model
- Password policy enforcement
- MFA implementation (if any)

### 4. Data Security & Storage
- Sensitive data handling patterns
- Encryption at rest and in transit
- Database access patterns
- File storage and access controls

### 5. Attack Surface Analysis
For each entry point:
```
Endpoint: POST /api/users/search
File: src/controllers/userController.js:42
Parameters: query (body), page (query)
Auth required: Yes (any role)
Validation: Partial (query not sanitized before DB call)
Risk: HIGH — potential SQL injection
```

### 6. XSS Sinks and Render Contexts
List every location where user input is rendered without proper escaping:
```
Sink: res.render('profile', { bio: user.bio })
File: src/routes/profile.js:28
Context: HTML body (Handlebars template)
Escaping: None — raw triple-braces {{{bio}}}
Risk: HIGH — stored XSS
```

### 7. SSRF Sinks and External Requests
List every location where URLs are constructed from user input:
```
Sink: fetch(userProvidedUrl)
File: src/services/webhook.js:15
Validation: URL scheme check only (http/https)
Bypass: DNS rebinding, IPv6, decimal IP
Risk: MEDIUM — SSRF via webhook URL
```

### 8. Critical File Paths
Categorized list of files that vulnerability and exploitation agents should prioritize:
- **Authentication**: file paths
- **Authorization**: file paths
- **Input handling**: file paths
- **Database queries**: file paths
- **External requests**: file paths
- **Configuration**: file paths

### 9. Taint Chain Catalog

**This is the most critical output section.** For every confirmed vulnerable taint chain, provide a structured entry. This catalog directly maps to exploitation queue entries in Phase 4.

| # | Sink Location | Sink Type | Slot Type | Source | Taint Chain | Sanitization | Applied vs Correct Defense | Verdict | Confidence | WSTG Test |
|---|---------------|-----------|-----------|--------|-------------|--------------|---------------------------|---------|------------|-----------|
| 1 | profile.js:28 | XSS (stored) | HTML-body | req.body.bio | body → DB.update() → DB.find() → template `{{{bio}}}` | None | None vs HTML entity encoding | VULNERABLE | High | INPV-02 |
| 2 | webhook.js:15 | SSRF | REDIR-url | req.body.url | body → fetch(url) | scheme check only | Scheme check vs Destination whitelist | NEEDS TESTING | Medium | INPV-19 |
| 3 | search.js:42 | SQLi | SQL-val | req.query.q | query → `"SELECT * WHERE name LIKE '%" + q + "%'"` | None (string concat) | None vs Parameterized query | VULNERABLE | High | INPV-05 |
| 4 | exec.js:10 | CMDi | CMD-argument | req.body.filename | body → `exec("convert " + filename)` | Regex strips `;|&` | Regex blocklist vs Array-based execution | NEEDS TESTING | Medium | INPV-12 |

**Slot Type Classification**: Use `get_slot_types(category)` to look up the correct defense for each slot type. The slot type determines what defense is ACTUALLY needed — a general vuln class (e.g., "SQLi") is insufficient because SQL-val needs parameterized queries but SQL-ident needs a whitelist.

**For each VULNERABLE or NEEDS TESTING chain, include the full trace:**

```
TAINT CHAIN #1: Stored XSS via bio field
SINK: res.render('profile', { bio: user.bio })  [profile.js:28]
SLOT TYPE: HTML-body
CORRECT DEFENSE: HTML entity encoding (&lt; &gt; &amp;)
APPLIED DEFENSE: None
  ← user.bio from User.findById(req.params.id)  [profile.js:22]
  ← DB stored value from User.update({ bio: req.body.bio })  [profile.js:55]
  ← req.body.bio (user-controlled POST parameter)

SANITIZATION: None on any path segment
POST-SANITIZATION CONCAT: N/A
VERDICT: VULNERABLE — user input reaches HTML-body sink with no encoding
CONFIDENCE: High
WITNESS PAYLOAD: <img src=x onerror=alert(1)>  (stored in bio, rendered in profile)
```

**Rules for the Taint Chain Catalog:**
- Only include chains that are VULNERABLE or NEEDS TESTING — do not catalog SAFE chains
- **MUST include slot type** — use `get_slot_types()` to classify each sink position
- **MUST compare applied defense vs correct defense** — wrong defense for the slot type = VULNERABLE
- Include exact file:line references for every hop in the chain
- Note ALL sanitization on the path, even if insufficient
- Flag post-sanitization concatenation explicitly
- Provide a witness payload (minimal PoC input to demonstrate the vulnerability)
- Map each chain to a WSTG test ID for Phase 4 targeting
