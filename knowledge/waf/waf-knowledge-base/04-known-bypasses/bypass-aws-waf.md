---
id: WAF-BYPASS-004
title: AWS WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# AWS WAF Bypass Payloads

## SQLi Bypasses

1. `1' OR '1'='1` with case variation
2. Comment-based bypasses
3. NULL byte injection

## XSS Bypasses

1. `<svg onload=alert(1)>`
2. `<img src=x onerror=alert(1)>`

## Technique Notes

- AWS WAF managed rules are signature-based and can be evaded with simple obfuscation
- Custom rule sets are more effective but often incomplete
- AWS WAF does not inspect compressed content by default
