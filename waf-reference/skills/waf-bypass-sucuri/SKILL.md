---
name: waf-bypass-sucuri
description: Skill for bypassing Sucuri CloudProxy WAF using event handler XSS, HTTP smuggling, and known bypass patterns. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 8
---

# Sucuri CloudProxy WAF Bypass

## Crown Jewel Targets

- WordPress sites behind Sucuri
- Sites using free Sucuri plan (limited rules)
- Origin IPs discoverable via DNS history

## Attack Surface Signals

- `Server: Sucuri` or `Server: Cloudproxy` header
- "Access Denied - Sucuri Website Firewall" block page
- `X-Sucuri-ID` header
- "Sucuri.net" in block page references

## Step-by-Step Methodology

1. Confirm Sucuri presence: check for Sucuri/Cloudproxy Server header
2. Test standard XSS - expect block
3. Test event handler-based XSS:
   - `<svg onload=alert(1)>`
   - `<body onload=alert(1)>`
   - `<details open ontoggle=alert(1)>`
   - `<input autofocus onfocus=alert(1)>`
4. Test HTTP request smuggling techniques
5. Try DNS history to find origin IP
6. Test encoding variations

## Payloads

```html
<!-- Event handler XSS bypasses -->
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- Encoding -->
%3Csvg%20onload=alert(1)%3E
```

## Common Root Causes

- Sucuri's WAF focuses on content-based signatures
- Event handler diversity creates gaps
- Origin IP bypass invalidates WAF entirely
- HTTP smuggling exploits proxy discrepancies

## Gate 0 Validation

- [ ] Have I confirmed Sucuri presence?
- [ ] Have I tried event handler XSS?
- [ ] Have I attempted origin IP discovery via DNS history?
