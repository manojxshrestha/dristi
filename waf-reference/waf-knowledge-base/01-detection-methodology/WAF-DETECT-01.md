---
id: WAF-DETECT-01
title: Where to Look for WAFs
category: Detection Methodology
severity_range: Informational-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-DETECT-01: Where to Look for WAFs

## Summary

WAFs can be detected by examining specific indicators in HTTP responses, including ports, cookies, headers, response codes, and page content. This test covers the primary locations to inspect when determining if a WAF is present.

## Test Objectives

- Identify WAF presence through network-level indicators
- Detect WAFs via HTTP response artifacts
- Recognize WAF-specific behavior patterns

## Detection Points

1. **Common Ports**: WAFs often operate on ports 80, 443, 8000, 8080, 8888
2. **WAF Cookies**: Look for WAF-specific cookies in responses (e.g., Citrix Netscaler, Yunsuo)
3. **Separate Headers**: Some WAFs add unique headers (e.g., Anquanbao, AWS WAF)
4. **Altered Headers**: WAFs may modify existing headers (e.g., Netscaler, Big-IP)
5. **Server Header**: The `Server` header may reveal WAF presence (e.g., Approach, WTS WAF)
6. **Response Content**: Error pages often contain WAF branding (e.g., DotDefender, Armor, SiteLock)
7. **Unusual Response Codes**: Some WAFs return non-standard codes (e.g., WebKnight returns 999, 360 WAF returns 493)

## Detection Criteria

If any of the above indicators are found, a WAF is likely present and should be fingerprinted using WAF-DETECT-02.

## Remediation

Understanding WAF presence informs the choice of evasion techniques for subsequent testing.
