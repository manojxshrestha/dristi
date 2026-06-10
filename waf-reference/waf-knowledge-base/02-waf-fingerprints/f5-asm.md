---
id: WAF-FP-136
title: F5 Asm WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# F5 Asm WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'The requested URL was rejected' | See detection details |

## Detailed Indicators

- Body: 'The requested URL was rejected'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "f5-asm"
```

## References

- https://github.com/0xInfection/Awesome-WAF
