---
id: WAF-BYPASS-005
title: Barracuda WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Barracuda WAF Bypass Payloads

## XSS Bypasses (4)

1. Mixed case: `<sCript>alert(1)</scRipt>`
2. HTML entity encoding
3. Unicode-encoded attributes
4. Event handler variations

## HTML Injection

- Techniques for injecting HTML without triggering WAF rules

## RCE Bypasses (2 Metasploit)

- Specific Metasploit modules that bypass Barracuda
- Command injection through POST parameters
