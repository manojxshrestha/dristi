---
description: Pipeline Phase 10 — Evidence collection: requests, screenshots, collaborator
mode: all
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# CAPTURE

Collect sanitized evidence for each confirmed finding. Each finding gets its own evidence directory.

## ⚠ Mandatory Setup
**Working directory:** Run from repo root. Verify `pwd` == repo root. If not, `cd $DRISTI_ROOT`.  
**Engagement ID:** Use `default-engagement` unless user explicitly specifies otherwise. Never invent custom IDs.

## Browser Hygiene (Mandatory)

Every browser operation leaks a page unless explicitly closed. Always:
1. `playwright_browser_navigate(url=...)` or `playwright_browser_take_screenshot(type='png', filename=<full_path>)`
2. `playwright_browser_close()` — immediately after, every time

**⚠ ALWAYS pass `filename` to `playwright_browser_take_screenshot()`** — without it, Playwright saves to the current working directory (repo root), creating messy artifacts. Use the engagement evidence path:
```
playwright_browser_take_screenshot(type='png', filename=runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<domain>/evidence/<finding-id>/screenshot.png)
```

Never leave open pages. They accumulate memory and break subsequent phases.

## Input

Get confirmed findings from Phase 6:
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
mkdir -p runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<domain>/evidence/<finding-id>/
curl -sv <poc-command> 2>&1 > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<domain>/evidence/<finding-id>/request.txt
```

### Step 3: Screenshot via Playwright (ALL findings — mandatory)

Every finding gets browser evidence. Use Playwright, not curl screenshots:

```python
EVIDENCE_DIR="runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<domain>/evidence/<finding-id>"
mkdir -p "$EVIDENCE_DIR"

# Navigate to the PoC URL or trigger
playwright_browser_navigate(url=<poc-url>)

# If the finding is authenticated, load cookies first (from Phase 2.5)
# playwright_browser_navigate(url="https://app.target.com"  # session preserved from auth)

# Screenshot showing visible evidence (URL bar, payload reflection, alert box)
playwright_browser_take_screenshot(
    type='png',
    filename="$EVIDENCE_DIR/screenshot.png"
)

# Capture browser console for CSP violations, JS errors, XSS proof
playwright_browser_console_messages(level='error')
playwright_browser_console_messages(level='warning')

# Capture network requests for HAR-style evidence
playwright_browser_network_requests(static=False)
```

Also capture the raw HTTP exchange as backup:
```bash
curl -sv <poc-command> 2>&1 > "$EVIDENCE_DIR/request.txt"
```

### Step 4: Check OOB Interactions (if applicable)
For blind SSRF, blind XXE, blind SQLi, log4shell — check Burp Collaborator:
```
burp_get_collaborator_interactions(payloadId=<id>)
```
Save any interaction evidence to `runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<domain>/evidence/<finding-id>/collaborator.txt`

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

### Step 7: Generate PoC Report
After all evidence is collected, generate the per-finding PoC report in the program-submission format:

```
bash scripts/generate_poc_report.sh <engagement-id> all
```

This creates `runtime/engagements/<engagement-id>/evidence/<finding-id>/poc-report.md` for every finding, pre-filled with the finding title, description, affected URL, evidence file list, and PoC output. Sections marked `[add ...]` require manual input — fill these in before submission.

The PoC report follows the standard template at `templates/poc-report-template.md` with sections: Summary, Shops Used to Test, Relevant Request IDs, Steps To Reproduce, Supporting Material.

## Verification

- [ ] `@evidence-hygiene` loaded for redaction protocol
- [ ] Every confirmed finding has raw HTTP evidence captured
- [ ] Screenshot taken for DOM/visual bugs
- [ ] Collaborator interactions checked for OOB findings
- [ ] Redaction applied to all evidence (cookies, PII, tokens stripped)
- [ ] Evidence files exist at `runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<domain>/evidence/<finding-id>/`
- [ ] Deliverable saved for Phase 11 consumption

Proceed to Phase 11 (`@validate`) when all findings have clean evidence.
