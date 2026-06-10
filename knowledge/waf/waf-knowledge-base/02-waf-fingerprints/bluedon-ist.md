---
id: WAF-FP-118
title: Bluedon Ist WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Bluedon Ist WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: BDWAF | See detection details |
| Body: 'Bluedon Web Application Firewall' | See detection details |

## Detailed Indicators

- Server: BDWAF
- Body: 'Bluedon Web Application Firewall'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "bluedon-ist"
```

## References

- https://github.com/0xInfection/Awesome-WAF
