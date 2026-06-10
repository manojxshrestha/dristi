---
id: WAF-FP-150
title: Litespeed WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Litespeed WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: LiteSpeed | See detection details |
| Body: 'Proudly powered by LiteSpeed Web Server' | See detection details |

## Detailed Indicators

- Server: LiteSpeed
- Body: 'Proudly powered by LiteSpeed Web Server'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "litespeed"
```

## References

- https://github.com/0xInfection/Awesome-WAF
