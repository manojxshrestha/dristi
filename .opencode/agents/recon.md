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
# Single domain:
bash scripts/tools/subdomain_enum.sh <target>

# Multiple domains in parallel (faster for 2+ targets):
bash scripts/tools/batch_subdomain_enum.sh -j 3 domain1.com domain2.com domain3.com

# Or from a file (one domain per line):
bash scripts/tools/batch_subdomain_enum.sh -j 3 -f domains.txt

# DNS brute-force
bash scripts/tools/dns_bruteforce.sh <target>
```

**For each live host, answer:** Is this Cloudflare-protected? `curl -svI <host>` — look for `cf-*` headers. If yes, note it and redirect focus to non-CF hosts.

**httpx now enriches output with status codes, titles, tech detection, and web server** (`live_domains.txt`). Scan this file for:
- `[401]` or `[403]` statuses → likely auth-gated (feeds Q3)
- `[200]` with interesting titles → "Admin", "Dashboard", "Login" → high-value targets
- Tech stack in output → Express/Spring/Django/Laravel/Golang — each has different attack surface
- Non-standard ports or redirects → potential bypass targets

### Step 2: Crawl & URL Collection

```bash
bash scripts/tools/web_crawl.sh <target>
```

**Note:** `web_crawl.sh` now has timeouts on hakrawler/katana → clean CF-blocked warnings, 0s wasted. **gau removed** — waymore covers Wayback Machine better (340K+ vs 0), `~/.gau.toml` left for manual use.

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
bash scripts/tools/param_extract.sh <target>
bash scripts/tools/param_discovery.sh <target>
```

**For each parameter found, answer:**
```
param=<name> endpoint=<url> auth=[yes|no|unknown] method=[GET|POST] type=[query|body|path|header]
```

### Step 4: Technology Detection

```bash
bash scripts/tools/auto_nuclei.sh <target>
```

**Look for:** framework type (Express, Spring, Django, Laravel, Rails), GraphQL, WebSocket, file upload endpoints, admin panels, debug endpoints.

Technology choice matters for Question 1 — different frameworks accept input differently (Rails = mass assignment, Express = prototype pollution, Spring = SpEL injection).

### Step 5: Secrets & Sensitive Data

```bash
bash scripts/tools/cariddi_scan.sh <target>
bash scripts/tools/auto_secrets.sh <target>
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

### Step 7: S3 / Cloud Bucket Scan

```bash
bash scripts/tools/s3_buckets.sh <target>
```

Runs cloud_enum on subdomains + s3scanner + trufflehog:

| Tool | What it does | Output |
|------|-------------|--------|
| cloud_enum | Keyword-based bucket enumeration (AWS, Azure, GCP, DO) | `clouds/cloud_enum_results.jsonl`, `clouds/cloud_assets.txt` |
| s3scanner | Scans all discovered subdomains for valid S3 buckets | `clouds/s3buckets.txt` |
| trufflehog | Scans public buckets for leaked secrets | `clouds/s3_trufflehog.txt`, `clouds/cloud_enum_trufflehog.txt` |

**For each cloud bucket, answer:**
- `[PUBLIC_BUCKET]` — accessible without auth, accepts GET/PUT/DELETE
- `[AUTH_BUCKET]` — requires cloud credentials (AWS keys, GCP SA, Azure SAS)
- `[OPEN_UPLOAD]` — public + accepts PUT — HIGHEST priority (write access without auth)
- `[LEAKED_SECRET]` — trufflehog found credentials in the bucket

If `cloud_enum` is not installed, run first: `bash scripts/tools/phase-intel.sh --install`

### Step 8: Compiled Endpoint Triage

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
