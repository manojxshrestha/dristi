---
id: WAF-FP-004
title: Imperva Incapsula WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Imperva Incapsula WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie | `visid_incap_` |
| Cookie | `incap_ses_` |
| Header | `X-Iinfo` |
| Response Body | "Powered By Incapsula" |
| Response Body | "Incapsula incident ID" |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "incap\|incapsula\|x-iinfo"
```

## References
- https://www.imperva.com/products/web-application-firewall/
