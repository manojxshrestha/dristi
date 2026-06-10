---
id: WAF-BYPASS-003
title: ModSecurity WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# ModSecurity WAF Bypass Payloads

## XSS Bypasses (CRS 3.2)

- Various encoding and obfuscation techniques that evade CRS rules
- Using non-standard event handlers
- Protocol-level manipulation

## RCE Bypasses (PL1-PL3)

- Techniques that bypass OWASP CRS paranoia levels 1 through 3
- Command injection through encoding
- File upload-based RCE bypasses

## SQLi Bypasses (7+)

1. `1' OR 1=1-- -` variants with encoding
2. Time-based blind with different delay functions
3. Error-based with special characters
4. UNION-based with null byte injection
5. Comments inside keywords: `SEL/**/ECT`
6. Double URL encoding
7. Hex encoding of strings

## Technique Notes

- ModSecurity CRS paranoia levels increase detection but also increase false positives
- Level 1 is easy to bypass; Level 4 is very difficult
- Behavioral detection (anomaly scoring) is harder to bypass than signature-based
