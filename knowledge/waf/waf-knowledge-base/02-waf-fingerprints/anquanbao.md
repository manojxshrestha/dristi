---
id: WAF-FP-021
title: Anquanbao (AQ/Azure) WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Anquanbao (AQ/Azure) WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `X-Powered-By-Anquanbao` |
| Response Body | `/aqb_cc/error/` in block page URL |
| Response Code | 405 (Method Not Allowed) |
| Response Body | "Anquanbao" branding in block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "anquanbao\|x-powered-by-anquanbao\|aqb_cc"
```

## References
- https://www.anquanbao.com/
