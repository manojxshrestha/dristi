---
id: WAF-FP-192
title: Stingray WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Stingray WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Code 403 or 500 | See detection details |
| X-Mapping header | See detection details |

## Detailed Indicators

- Code 403 or 500
- X-Mapping header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "stingray"
```

## References

- https://github.com/0xInfection/Awesome-WAF
