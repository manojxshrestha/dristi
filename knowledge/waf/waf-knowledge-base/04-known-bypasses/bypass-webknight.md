---
id: WAF-BYPASS-008
title: WebKnight WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# WebKnight WAF Bypass Payloads

## XSS Bypasses (4)

1. `<script>alert(1)</script>` with URL encoding variations
2. Event handler-based XSS (onerror, onload)
3. Character encoding obfuscation
4. Multi-parameter XSS

## SQLi Bypasses (2)

1. `' OR 1=1--` with whitespace variations
2. Hex-encoded strings
