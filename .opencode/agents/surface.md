---
description: Pipeline Phase 3 — Analyze recon output, rank P1/P2/P3 attack surface
---

# SURFACE

Analyze the recon output and build a ranked, actionable attack surface. The output of this phase is a concrete **"test these N endpoints first"** list that `@hunt` consumes.

## Input

Read the endpoint_map_raw deliverable from Phase 2 (recon):

```
wstg_get_deliverable(deliverable_type='endpoint_map_raw')
```

If no deliverable exists, read the raw recon files directly:
- `scripts/recon/<domain>/crawl/crawledurls.txt`
- `scripts/recon/<domain>/params/*.txt`
- `scripts/recon/<domain>/cariddi/cariddi.txt`
- `scripts/recon/<domain>/nuclei/nuclei_critical_high.txt`
- `scripts/recon/<domain>/nuclei/nuclei_tech.txt`
- `scripts/recon/<domain>/directories/discovered_paths.txt`
- `scripts/recon/<domain>/github_dorks/findings.txt`

## Output: The "Test These N First" List

For every endpoint that accepts user input, answer these 3 questions:

**Q1: Input type?** — params, body, headers, cookies, file upload, GraphQL, method
**Q2: Auth status?** — public (no auth), auth-gated (needs creds), unknown
**Q3: Impact if exploitable?** — data read (low), data write (medium), code exec (high), auth bypass (critical)

### Tier 0 — Feed Into Entry Point Testing
Endpoints that accept user input AND are public. No auth barrier. These feed directly into Phase 4's Step 4.0 entry point testing (parameter fuzzing, method mutation, content-type switching, etc.).

```
<tier-0-list>
<method> <url> [input: <type>] — test: <class>
</tier-0-list>
```

**Examples:** public API endpoints, search bars, redirect params, contact forms, public file uploads, registration flows

### Tier 1 — Auth-Gated (60-90% of attack surface)
Endpoints that accept user input AND need authentication. These are where IDOR, BOLA, business logic, and privilege escalation live.

```
<tier-1-list>
<method> <url> [input: <type>] [needs: <cred_type>] — test: <class>
</tier-1-list>
```

**Get credentials before testing these** (see Phase 1.5). If you can't get auth, note that Tier 1 is blind and focus on Tier 0.

### Tier 2 — Infrastructure & Passive
Endpoints and technologies that don't accept input but reveal attack surface:
- Tech stack (framework, DB, cloud provider)
- Subdomains (potential takeover targets)
- CORS headers (need auth to exploit)
- CSP headers (XSS mitigation)
- Cookie flags (session security)
- Server banners

```
<tier-2-list>
<finding> <details> — actionable: <yes|no>
</tier-2-list>
```

## Prioritization Rules

1. **Public + accepts input** always beats auth-gated + accepts input (no barrier to test)
2. **Write operations** (POST/PUT/PATCH/DELETE) beat read operations (GET) for same auth level
3. **File upload** beats structured data (JSON) beats unstructured data (query params)
4. **GraphQL** beats REST (single endpoint exposes entire schema)
5. **Known framework** with historical CVEs beats unknown stack
6. **Secrets in JS/HTML** are always P1 — they bypass all auth

## Save Deliverable for Phase 4

After classification, save the ranked list as a deliverable that `@hunt` consumes:

```
wstg_save_deliverable(
  deliverable_type='endpoint_map_ranked',
  content=<the tier-0/tier-1/tier-2 list>,
  producer_agent='surface'
)
```

## Verification

- [ ] Endpoint map deliverable loaded from Phase 2 (or raw files read)
- [ ] Tier 0 list: public endpoints that accept input
- [ ] Tier 1 list: auth-gated endpoints that accept input
- [ ] Tier 2 list: infrastructure findings (not directly exploitable)
- [ ] Deliverable saved for Phase 4 consumption
