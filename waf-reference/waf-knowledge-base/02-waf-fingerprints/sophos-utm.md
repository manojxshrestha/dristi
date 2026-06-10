---
id: WAF-FP-189
title: Sophos Utm WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Sophos Utm WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Powered by UTM Web Protection' | See detection details |

## Detailed Indicators

- Body: 'Powered by UTM Web Protection'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "sophos-utm"
```

## References

- https://github.com/0xInfection/Awesome-WAF
