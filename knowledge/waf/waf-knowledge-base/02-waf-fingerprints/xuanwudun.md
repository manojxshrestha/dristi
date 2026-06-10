---
id: WAF-FP-215
title: Xuanwudun WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Xuanwudun WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| admin.dbappwaf.cn reference | See detection details |

## Detailed Indicators

- admin.dbappwaf.cn reference

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "xuanwudun"
```

## References

- https://github.com/0xInfection/Awesome-WAF
