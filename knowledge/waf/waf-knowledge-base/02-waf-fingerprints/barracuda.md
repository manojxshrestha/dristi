---
id: WAF-FP-007
title: Barracuda WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Barracuda WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie | `barra_counter_session=` |
| Cookie | `barracuda_` prefix cookies |
| Response Code | 403 with "You have been blocked" |
| Response Body | "You have been blocked because of fraudulent activity" |
| Response Body | "Barracuda Networks" branding in block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "barracuda\|barra_counter"
```

## References
- https://www.barracuda.com/products/web-application-firewall
