---
id: WAF-FP-113
title: Barikode WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Barikode WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'BARIKODE' | See detection details |
| Body: 'Forbidden Access' | See detection details |

## Detailed Indicators

- Body: 'BARIKODE'
- Body: 'Forbidden Access'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "barikode"
```

## References

- https://github.com/0xInfection/Awesome-WAF
