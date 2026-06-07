---
description: Pipeline Phase 5 — Evidence collection: requests, screenshots, collaborator
---

# CAPTURE

Guide the user through collecting evidence for each confirmed finding.

1. Show the list of confirmed findings (from `get_findings()`)
2. Ask: "Which finding do you want to capture evidence for?"

For each finding:
1. **Request/Response** — Use curl or Burp to re-execute the PoC and save the raw HTTP exchange
2. **Screenshots** — Use Playwright to capture the browser view showing the vulnerability
3. **OOB interactions** — If applicable, check `get_collaborator_interactions()` via Burp
4. **Hygiene** — Invoke `@evidence-hygiene` to redact cookies, PII, other users' data
5. **Save** — Store sanitized evidence as engagement deliverables

3. After all findings have evidence captured, ask: "Ready to validate findings? Type `@validate` to proceed."
