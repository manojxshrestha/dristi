---
id: WAF-FP-135
title: Expression Engine WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Expression Engine WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Invalid URI' | See detection details |
| Body: 'Invalid GET Request' | See detection details |

## Detailed Indicators

- Body: 'Invalid URI'
- Body: 'Invalid GET Request'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "expression-engine"
```

## References

- https://github.com/0xInfection/Awesome-WAF
