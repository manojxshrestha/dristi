---
id: WAF-FP-161
title: Nullddos WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Nullddos WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: NullDDoS System | See detection details |

## Detailed Indicators

- Server: NullDDoS System

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "nullddos"
```

## References

- https://github.com/0xInfection/Awesome-WAF
