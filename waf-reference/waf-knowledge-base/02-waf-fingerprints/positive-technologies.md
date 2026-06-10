---
id: WAF-FP-167
title: Positive Technologies WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Positive Technologies WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Forbidden' with Request ID in yyyy-mm-dd format | See detection details |

## Detailed Indicators

- Body: 'Forbidden' with Request ID in yyyy-mm-dd format

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "positive-technologie"
```

## References

- https://github.com/0xInfection/Awesome-WAF
