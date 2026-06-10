---
id: WAF-FP-022
title: Deny-All WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Deny-All WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie | `sessioncookie` (Deny-All specific) |
| Response Body | "Condition Intercepted" |
| Response Body | "Deny-All" branding in block page |
| Response Code | 403 with Deny-All block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "deny-all\|condition intercepted\|sessioncookie"
```

## References
- https://www.denyall.com/
