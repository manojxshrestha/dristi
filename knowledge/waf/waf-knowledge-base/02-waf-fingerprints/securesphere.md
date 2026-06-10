---
id: WAF-FP-181
title: Securesphere WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Securesphere WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: Error in h2 | See detection details |
| Title: Error | See detection details |

## Detailed Indicators

- Body: Error in h2
- Title: Error

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "securesphere"
```

## References

- https://github.com/0xInfection/Awesome-WAF
