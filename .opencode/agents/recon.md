---
description: Pipeline Phase 2 — Full recon: subdomains, live hosts, crawl, params, nuclei, secrets
---

# RECON

## ⚠ Auth Warning

You are about to map infrastructure. **Without an authenticated session, you will miss:**
- IDOR / BOLA
- Business logic flaws
- Session management issues
- Privilege escalation
- Real rate limiting
- Authenticated API misconfigurations
- Any finding that requires a logged-in state

**If the target has an auth wall, stop and get credentials first** (see `@autopilot` Phase 1.5). Recon without auth is useful for infrastructure mapping, but your crawl results will be incomplete, your parameter extraction will miss authenticated endpoints, and your nuclei scan will only find public CVEs.

If you proceed without auth, label every finding `[UNAUTHENTICATED]`.

## The Goal: Answer 3 Questions

Every tool you run during recon must help answer these questions. Everything else (CSP headers, cookie flags, server banners) is nice-to-know but doesn't find exploits.

### Question 1: Which endpoints accept user input?
- Parameters (GET/POST/JSON/XML)
- Request body (file upload, JSON body, form data)
- Headers (User-Agent, Referer, X-Forwarded-For, custom headers)
- Cookies
- File paths (LFI/RFI candidates)
- URL redirect params
- Content-Type (accepts different formats)
- HTTP method (accepts POST where GET is expected, etc.)

### Question 2: Which of those are public? (no auth required)
- Returns data without Authorization header or session cookie
- Login, register, password reset, public API endpoints
- Static resources that leak data (JS bundles with API keys, config files)
- SSRF targets (URL params that make server-side requests)

### Question 3: Which of those have auth? (need credentials)
- Returns 401/403 without auth header/session
- Require specific role (admin, user, org)
- Rate-limited differently with vs without auth
- Return different data when authenticated

## Recon Workflow

### Step 1: Subdomain & Infrastructure Discovery

Run these to find the attack surface boundaries:

```bash
# Subdomains
bash scripts/tools/subdomain_enum.sh <target>
# DNS brute-force
bash scripts/tools/dns_bruteforce.sh <target>
# Live host discovery
httpx -l scripts/recon/<target>/all_subdomains.txt -o scripts/recon/<target>/live_hosts.txt
```

**For each live host, answer:** Is this Cloudflare-protected? `curl -svI <host>` — look for `cf-*` headers. If yes, note it and redirect focus to non-CF hosts.

### Step 2: Crawl & URL Collection

```bash
bash scripts/tools/web_crawl.sh -l scripts/recon/<target>/live_hosts.txt
```

**From crawled URLs, isolate the input-accepting set:**
```
# URLs with query params (already has ?key=value)
scripts/recon/<target>/crawl/crawledurls.txt

# Wayback URLs (historical endpoints + params)
scripts/recon/<target>/wayback/urllist.txt
```
For each URL with parameters, note whether it's:
- `[AUTH_REQUIRED]` — returns 401/403 without token
- `[PUBLIC]` — returns data without auth
- `[UNKNOWN]` — haven't tested yet

### Step 3: Parameter Extraction

```bash
bash scripts/tools/param_extract.sh scripts/recon/<target>/
bash scripts/tools/param_discovery.sh <target>
```

**For each parameter found, answer:**
```
param=<name> endpoint=<url> auth=[yes|no|unknown] method=[GET|POST] type=[query|body|path|header]
```

### Step 4: Technology Detection

```bash
bash scripts/tools/auto_nuclei.sh scripts/recon/<target>/live_hosts.txt
```

**Look for:** framework type (Express, Spring, Django, Laravel, Rails), GraphQL, WebSocket, file upload endpoints, admin panels, debug endpoints.

Technology choice matters for Question 1 — different frameworks accept input differently (Rails = mass assignment, Express = prototype pollution, Spring = SpEL injection).

### Step 5: Secrets & Sensitive Data

```bash
bash scripts/tools/cariddi_scan.sh scripts/recon/<target>/live_hosts.txt
bash scripts/tools/auto_secrets.sh scripts/recon/<target>/
```

**Secrets answer Question 2** — hardcoded API keys, tokens, and passwords in JS/HTML are public by definition. Every secret found is a P1 finding because it bypasses all auth.

### Step 6: Directory & Endpoint Discovery

```bash
bash scripts/tools/dir_bruteforce.sh <target>
bash scripts/tools/bypass_403.sh <target>
bash scripts/tools/vhost_fuzz.sh <target>
bash scripts/tools/cloud_recon.sh <target>
```

**For each discovered path, answer:**
- `[INPUT]` — accepts input (upload, search, form, API endpoint)
- `[NO_INPUT]` — static page, no user-controlled data
- `[AUTH_GATE]` — requires authentication

**For cloud buckets (S3, GCP, Azure blobs), also answer:**
- `[PUBLIC_BUCKET]` — accessible without auth, accepts GET/PUT/DELETE
- `[AUTH_BUCKET]` — requires cloud credentials (AWS keys, GCP SA, Azure SAS)
- `[OPEN_UPLOAD]` — public + accepts PUT — HIGHEST priority (write access without auth)

### Step 7: Compiled Endpoint Triage

After all tools have run, compile the answers to the 3 questions:

**Input-accepting endpoints (public):**
```
<method> <url> <params|body|headers> [PUBLIC]
```

**Input-accepting endpoints (auth-gated):**
```
<method> <url> <params|body|headers> [AUTH_REQUIRED]
```

**Input-accepting endpoints (unknown auth):**
```
<method> <url> <params|body|headers> [AUTH_UNKNOWN]
```

This triage IS the output of recon. Everything else (CSP headers, cookie flags, server banners) is interesting but does not find exploits.

Save this triage via `wstg_save_deliverable(deliverable_type='endpoint_map_raw', content=<triage_markdown>)` for Phase 3 to consume.
