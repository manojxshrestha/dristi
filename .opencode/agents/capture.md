---
description: Pipeline Phase 5 — Evidence collection: requests, screenshots, collaborator
---

# CAPTURE

Collect sanitized evidence for each confirmed finding. Each finding gets its own evidence directory.

## Browser Hygiene (Mandatory)

Every browser operation leaks a page unless explicitly closed. Always:
1. `playwright_browser_navigate()` or `playwright_browser_take_screenshot()`
2. `playwright_browser_close()` — immediately after, every time

Never leave open pages. They accumulate memory and break subsequent phases.

## Input

Get confirmed findings from Phase 4:
```
wstg_get_findings(engagement_id=<eid>)
wstg_get_deliverable(deliverable_type='endpoint_map_ranked')
```

## Evidence Collection (per finding)

For EACH confirmed finding, execute these steps in order:

### Step 1: Load Redaction Protocol
```
@evidence-hygiene
```
Read the hygiene agent's redaction protocol before collecting any evidence.

### Step 2: Capture Raw HTTP Request/Response
Re-execute the PoC via curl and save the raw exchange:
```
mkdir -p scripts/recon/<domain>/evidence/<finding-id>/
curl -sv <poc-command> 2>&1 > scripts/recon/<domain>/evidence/<finding-id>/request.txt
```

### Step 3: Screenshot (if DOM/visual bug)
For reflected XSS, DOM XSS, clickjacking, or any visual proof:
```
playwright_browser_navigate(url=<poc-url>)
playwright_browser_take_screenshot(type='png', filename=scripts/recon/<domain>/evidence/<finding-id>/screenshot.png)
playwright_browser_close()
```

### Step 4: Check OOB Interactions (if applicable)
For blind SSRF, blind XXE, blind SQLi, log4shell — check Burp Collaborator:
```
burp_get_collaborator_interactions(payloadId=<id>)
```
Save any interaction evidence to `scripts/recon/<domain>/evidence/<finding-id>/collaborator.txt`

### Step 5: Apply Hygiene
- **Redact** cookies, auth headers, session tokens, API keys
- **Redact** PII: emails, names, IPs (unless target's own test data), other users' data
- **Strip** screenshot metadata (EXIF, GPS, device info)
- **Sanitize** HAR files if used

### Step 6: Save Sanitized Evidence
Store the clean evidence as engagement deliverables:
```
wstg_save_deliverable(deliverable_type='evidence', content=<clean-request+response>, producer_agent='capture')
```

## Verification

- [ ] `@evidence-hygiene` loaded for redaction protocol
- [ ] Every confirmed finding has raw HTTP evidence captured
- [ ] Screenshot taken for DOM/visual bugs
- [ ] Collaborator interactions checked for OOB findings
- [ ] Redaction applied to all evidence (cookies, PII, tokens stripped)
- [ ] Evidence files exist at `scripts/recon/<domain>/evidence/<finding-id>/`
- [ ] Deliverable saved for Phase 6 consumption

Proceed to Phase 6 (`@validate`) when all findings have clean evidence.
