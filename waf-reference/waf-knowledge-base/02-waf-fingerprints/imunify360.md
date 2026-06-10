---
id: WAF-FP-142
title: Imunify360 WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Imunify360 WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: imunify360-webshield | See detection details |
| Body: 'Powered by Imunify360' | See detection details |

## Detailed Indicators

- Server: imunify360-webshield
- Body: 'Powered by Imunify360'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "imunify360"
```

## References

- https://github.com/0xInfection/Awesome-WAF
