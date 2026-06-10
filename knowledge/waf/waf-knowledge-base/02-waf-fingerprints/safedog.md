---
id: WAF-FP-014
title: SafeDog WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# SafeDog WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: WAF/2.0` or `Server: SafeDog` |
| Cookie | `safedog` prefix cookies |
| Cookie | `safedog-flow-item` |
| Response Body | "SafeDog" branding in block page |
| Response Code | 403 with SafeDog block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "safedog\|waf/2.0"
```

## References
- https://www.safedog.cn/
