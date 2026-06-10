---
id: WAF-FP-130
title: Dosarrest WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Dosarrest WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-DIS-Request-ID header | See detection details |
| Server: DOSarrest | See detection details |

## Detailed Indicators

- X-DIS-Request-ID header
- Server: DOSarrest

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "dosarrest"
```

## References

- https://github.com/0xInfection/Awesome-WAF
