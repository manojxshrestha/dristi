---
id: WAF-FP-162
title: Onmessage Shield WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Onmessage Shield WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Engine: onMessage Shield header | See detection details |
| Blackbaud K-12 reference | See detection details |

## Detailed Indicators

- X-Engine: onMessage Shield header
- Blackbaud K-12 reference

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "onmessage-shield"
```

## References

- https://github.com/0xInfection/Awesome-WAF
