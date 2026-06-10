---
id: WAF-FP-114
title: Bekchy WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Bekchy WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Headers: 'Bekchy - Access Denied' | See detection details |
| Reference to bekchy.com/report | See detection details |

## Detailed Indicators

- Headers: 'Bekchy - Access Denied'
- Reference to bekchy.com/report

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "bekchy"
```

## References

- https://github.com/0xInfection/Awesome-WAF
