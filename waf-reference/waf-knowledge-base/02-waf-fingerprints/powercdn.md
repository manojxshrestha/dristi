---
id: WAF-FP-168
title: Powercdn WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Powercdn WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Via: powercdn.com | See detection details |
| X-Cache: powercdn.com | See detection details |
| X-CDN: PowerCDN | See detection details |

## Detailed Indicators

- Via: powercdn.com
- X-Cache: powercdn.com
- X-CDN: PowerCDN

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "powercdn"
```

## References

- https://github.com/0xInfection/Awesome-WAF
