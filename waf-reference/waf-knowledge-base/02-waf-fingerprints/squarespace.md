---
id: WAF-FP-190
title: Squarespace WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Squarespace WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Code 404 on malicious requests | See detection details |
| Body: BRICK-50 | See detection details |

## Detailed Indicators

- Code 404 on malicious requests
- Body: BRICK-50

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "squarespace"
```

## References

- https://github.com/0xInfection/Awesome-WAF
