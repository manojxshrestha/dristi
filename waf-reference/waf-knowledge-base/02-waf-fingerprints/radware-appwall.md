---
id: WAF-FP-016
title: Radware AppWall WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Radware AppWall WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `X-SL-CompState` |
| Response Body | "Unauthorized Activity Has Been Detected" |
| Response Body | "Case Number:" followed by a reference number |
| Response Body | "Radware" branding in block page |
| Response Code | 403 with Radware AppWall block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "radware\|x-sl-compstate\|unauthorized activity"
```

## References
- https://www.radware.com/products/appwall/
