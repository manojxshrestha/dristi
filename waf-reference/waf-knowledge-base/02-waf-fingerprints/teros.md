---
id: WAF-FP-195
title: Teros WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Teros WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie: st8id | See detection details |

## Detailed Indicators

- Cookie: st8id

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "teros"
```

## References

- https://github.com/0xInfection/Awesome-WAF
