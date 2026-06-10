---
id: WAF-FP-108
title: Arvancloud WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Arvancloud WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: ArvanCloud | See detection details |

## Detailed Indicators

- Server: ArvanCloud

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "arvancloud"
```

## References

- https://github.com/0xInfection/Awesome-WAF
