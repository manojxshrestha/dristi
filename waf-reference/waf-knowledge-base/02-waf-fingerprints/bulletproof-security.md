---
id: WAF-FP-119
title: Bulletproof Security WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Bulletproof Security WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: bpsMessage div | See detection details |
| WordPress security plugin | See detection details |

## Detailed Indicators

- Body: bpsMessage div
- WordPress security plugin

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "bulletproof-security"
```

## References

- https://github.com/0xInfection/Awesome-WAF
