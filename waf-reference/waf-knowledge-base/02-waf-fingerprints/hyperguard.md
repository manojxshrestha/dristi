---
id: WAF-FP-140
title: Hyperguard WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Hyperguard WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie: ODSESSION= | See detection details |

## Detailed Indicators

- Cookie: ODSESSION=

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "hyperguard"
```

## References

- https://github.com/0xInfection/Awesome-WAF
