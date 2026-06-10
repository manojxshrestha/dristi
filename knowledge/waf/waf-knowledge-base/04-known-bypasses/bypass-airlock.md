---
id: WAF-BYPASS-015
title: Airlock Ergon WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Airlock Ergon WAF Bypass Payloads

## SQLi Bypasses

1. UTF-8 overlong encoding sequences to bypass regex filters
2. Comment injection within SQL keywords

## Technique Notes

- Airlock is sensitive to properly formatted requests
- Overlong UTF-8 sequences can bypass signature detection
