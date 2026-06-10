---
id: WAF-BYPASS-017
title: DotDefender WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# DotDefender WAF Bypass Payloads

## Firewall Disable

- Techniques to disable DotDefender from functioning

## RCE

1. Command injection with obfuscated parameters
2. Encoding-based RCE payloads

## XSS Bypasses (4+)

1. `<script>` with encoding variations
2. Mixed case and broken syntax
3. Event handler-based XSS
4. Persistent XSS in stored fields

## Technique Notes

- DotDefender has known weaknesses with specific encoding patterns
- Multiple XSS bypasses have been documented
- RCE through obfuscation is possible
