---
description: Pipeline Phase 4 — Full recon: subdomains, live hosts, crawl, params, nuclei, secrets
mode: all
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
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

**If the target has an auth wall, stop and get credentials first** (see `@autopilot` Phase 2). Recon without auth is useful for infrastructure mapping, but your crawl results will be incomplete, your parameter extraction will miss authenticated endpoints, and your nuclei scan will only find public CVEs.

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

### Step 1: Subdomain Enumeration + DNS Bruteforce

```bash
# Single domain:
bash scripts/tools/subdomain_enum.sh <target>

# Multiple domains in parallel:
bash scripts/tools/batch_subdomain_enum.sh -j 3 domain1.com domain2.com domain3.com

# DNS brute-force
bash scripts/tools/dns_bruteforce.sh <target>
```

**Track:** `wstg_track_tool(tool_name='subdomain_enum', status='run', notes='Subdomain enumeration + DNS bruteforce')`

**For each live host, answer:** Is this Cloudflare-protected? `curl -svI <host>` — look for `cf-*` headers.

**httpx** enriches output with status codes, titles, tech detection, and web server. Scan for:
- `[401]`/`[403]` → auth-gated (feeds Q3)
- `[200]` with titles like "Admin", "Dashboard" → high-value
- Tech stack → Express/Spring/Django/Laravel — each has different attack surface

### Step 2: Web Crawling + Parameter Extraction

```bash
bash scripts/tools/web_crawl.sh <target>
bash scripts/tools/param_extract.sh <target>
bash scripts/tools/param_discovery.sh <target>
```

**Track:** `wstg_track_tool(tool_name='web_crawl', status='run', notes='Web crawling + parameter extraction')`

**From crawled URLs, isolate the input-accepting set:**
```
crawl/crawledurls.txt        # URLs with query params
wayback/urllist.txt          # Historical endpoints
```
For each: note `[AUTH_REQUIRED]`, `[PUBLIC]`, or `[UNKNOWN]`.

**For each parameter found:**
```
param=<name> endpoint=<url> auth=[yes|no|unknown] method=[GET|POST] type=[query|body|path|header]
```

### Step 3: Cariddi + Nuclei + Directory Bruteforce

```bash
bash scripts/tools/cariddi_scan.sh <target>
bash scripts/tools/auto_nuclei.sh <target>
bash scripts/tools/dir_bruteforce.sh <target>
```

**Track:** `wstg_track_tool(tool_name='cariddi_nuclei_dirbrute', status='run', notes='Cariddi + nuclei + directory bruteforce')`

**Look for:** framework type, GraphQL, WebSocket, file upload endpoints, admin panels, debug endpoints. Technology choice matters — different frameworks accept input differently (Rails = mass assignment, Express = prototype pollution, Spring = SpEL injection).

### Step 4: 403 Bypass + Vhost Fuzzing

```bash
bash scripts/tools/bypass_403.sh <target>
bash scripts/tools/vhost_fuzz.sh <target>
```

**Track:** `wstg_track_tool(tool_name='bypass403_vhost', status='run', notes='403 bypass + vhost fuzzing')`

### Step 5: Zone Transfer + Takeover Scanner

```bash
bash scripts/tools/zone_transfer.sh <target>
bash scripts/tools/takeover_scanner.sh <target>
```

**Track:** `wstg_track_tool(tool_name='zone_takeover', status='run', notes='Zone transfer + takeover scanner')`

### Step 6: Cloud Recon + CVE Scan + Secrets Discovery

```bash
bash scripts/tools/cloud_recon.sh <target>
bash scripts/tools/auto_secrets.sh <target>
bash scripts/tools/s3_buckets.sh <target>
```

**Track:** `wstg_track_tool(tool_name='cloud_cve_secrets', status='run', notes='Cloud recon + CVE scan + secrets discovery')`

Runs cloud_enum on subdomains + s3scanner + trufflehog:

| Tool | What it does | Output |
|------|-------------|--------|
| cloud_enum | Keyword-based bucket enumeration (AWS, Azure, GCP, DO) | `clouds/cloud_enum_results.jsonl` |
| s3scanner | Scans all discovered subdomains for valid S3 buckets | `clouds/s3buckets.txt` |
| trufflehog | Scans public buckets for leaked secrets | `clouds/s3_trufflehog.txt` |

**For each cloud bucket:** `[PUBLIC_BUCKET]`, `[AUTH_BUCKET]`, `[OPEN_UPLOAD]`, `[LEAKED_SECRET]`

If `cloud_enum` not installed: `bash scripts/tools/phase-intel.sh --install`

### Step 7: Answer 3 Triage Questions Per Endpoint

Compile answers to the 3 questions from all tool outputs above:

**Q1: Which endpoints accept user input?**
- Parameters (GET/POST/JSON/XML), request body, headers, cookies, file paths, URL redirect params, Content-Type, HTTP method

**Q2: Which of those are public? (no auth required)**
- Returns data without Authorization header
- Login, register, password reset, public API
- Static resources leaking data (JS bundles with API keys)

**Q3: Which of those have auth? (need credentials)**
- Returns 401/403 without auth
- Require specific role
- Rate-limited differently with vs without auth
- Return different data when authenticated

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

### Step 8: Save Endpoint Map Deliverable

`wstg_save_deliverable(deliverable_type='endpoint_map_raw', content=<triage_markdown>, producer_agent='recon')`

### Step 9: Gate Check

`wstg_phase_gate_check(phase_completed=1)`

If PASS → `wstg_save_checkpoint()` → proceed to Phase 5 SURFACE.
If FAIL → fix blockers, re-run gated steps, retry gate.
