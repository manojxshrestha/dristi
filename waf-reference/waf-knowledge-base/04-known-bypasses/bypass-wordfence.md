---
id: WAF-BYPASS-007
title: Wordfence WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Wordfence WAF Bypass Payloads

## XSS Bypasses (4+)

1. `/?author=1` (username enumeration via author ID)
2. Direct admin script access bypass
3. REST API endpoint access
4. Various payload encoding techniques

## HTML Injection

- Comment posting with HTML that bypasses Wordfence filters

## Technique Notes

- Wordfence is a WordPress plugin; its WAF operates at the application level
- Blocking is often based on known attack patterns; zero-day techniques are effective
- Wordfence learning mode temporarily allows all traffic
