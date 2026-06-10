---
id: WAF-FP-019
title: DotDefender WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# DotDefender WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `X-dotDefender-denied` |
| Response Body | "dotDefender Blocked Your Request" |
| Response Body | "dotDefender" branding in block page |
| Response Code | 403 with DotDefender block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "dotdefender\|x-dotdefender-denied"
```

## References
- https://www.applicure.com/products/dotdefender
