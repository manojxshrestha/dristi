---
id: WAF-FP-020
title: NAXSI WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# NAXSI WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `X-Data-Origin: naxsi/waf` |
| Response Body | "This Request Has Been Blocked By NAXSI" |
| Response Body | "NAXSI" in block page |
| Response Code | 403 with NAXSI block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "naxsi\|x-data-origin"
```

## References
- https://github.com/nbs-system/naxsi
