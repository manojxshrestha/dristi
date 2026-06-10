---
id: WAF-FP-219
title: Zenedge WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Zenedge WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| /__zenedge/assets/ reference | See detection details |
| Server: ZENEDGE | See detection details |
| X-Zen-Fury header | See detection details |

## Detailed Indicators

- /__zenedge/assets/ reference
- Server: ZENEDGE
- X-Zen-Fury header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "zenedge"
```

## References

- https://github.com/0xInfection/Awesome-WAF
