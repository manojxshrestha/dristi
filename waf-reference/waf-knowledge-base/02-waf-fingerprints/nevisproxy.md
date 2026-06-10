---
id: WAF-FP-156
title: Nevisproxy WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Nevisproxy WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie: Navajo | See detection details |

## Detailed Indicators

- Cookie: Navajo

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "nevisproxy"
```

## References

- https://github.com/0xInfection/Awesome-WAF
