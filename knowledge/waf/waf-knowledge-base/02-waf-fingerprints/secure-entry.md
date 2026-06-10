---
id: WAF-FP-179
title: Secure Entry WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Secure Entry WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: Secure Entry Server | See detection details |

## Detailed Indicators

- Server: Secure Entry Server

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "secure-entry"
```

## References

- https://github.com/0xInfection/Awesome-WAF
