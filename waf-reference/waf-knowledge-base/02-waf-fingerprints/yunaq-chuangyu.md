---
id: WAF-FP-216
title: Yunaq Chuangyu WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Yunaq Chuangyu WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| 365cyd.com or 365cyd.net reference | See detection details |
| help.365cyd.com/cyd-error-help | See detection details |

## Detailed Indicators

- 365cyd.com or 365cyd.net reference
- help.365cyd.com/cyd-error-help

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "yunaq-chuangyu"
```

## References

- https://github.com/0xInfection/Awesome-WAF
