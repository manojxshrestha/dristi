---
id: WAF-FP-129
title: Distil WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Distil WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Distil-CS header | See detection details |
| Body: 'Pardon Our Interruption...' | See detection details |

## Detailed Indicators

- X-Distil-CS header
- Body: 'Pardon Our Interruption...'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "distil"
```

## References

- https://github.com/0xInfection/Awesome-WAF
