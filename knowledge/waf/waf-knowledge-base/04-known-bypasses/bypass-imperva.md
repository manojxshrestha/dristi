---
id: WAF-BYPASS-002
title: Imperva Incapsula WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Imperva Incapsula WAF Bypass Payloads

## XSS Bypasses (10+)

1. `<svg onload=alert(1)>` (sometimes passes)
2. `<img src=x onerror=alert(1)>`
3. `<body onload=alert(1)>`
4. Various encoding-based bypasses
5. Multi-parameter splitting techniques

## SQLi Bypasses

1. Parameter pollution approaches
2. Encoding-based SQLi

## Privilege Escalation

- Horizontal/direct object reference patterns that bypass Imperva rules

## Technique Notes

- Imperva is sensitive to request structure; modifying parameter order can bypass some rules
- Mixed encoding types are effective
