---
id: WAF-BYPASS-018
title: Fortinet FortiWeb WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Fortinet FortiWeb WAF Bypass Payloads

## XSS Bypasses (2)

1. `<svg onload=alert(1)>`
2. Encoding-based XSS with padding

## CSP Bypass

- POST/GET request manipulation with padding bytes
- CSP header bypass techniques

## Technique Notes

- FortiWeb's CSP enforcement can be bypassed with padding techniques
- POST body padding can mask XSS payloads
