---
id: WAF-BYPASS-009
title: Comodo cWatch WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Comodo cWatch WAF Bypass Payloads

## XSS Bypasses (2)

1. `<script>alert(1)</script>` with encoding
2. `<img src=x onerror=alert(1)>` (bypasses in some configurations)

## SQLi Bypasses

1. Standard SQLi with comment obfuscation
