---
id: WAF-FP-107
title: Armor Defense WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Armor Defense WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'This request has been blocked by Armor' | See detection details |
| Contact support message | See detection details |

## Detailed Indicators

- Body: 'This request has been blocked by Armor'
- Contact support message

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "armor-defense"
```

## References

- https://github.com/0xInfection/Awesome-WAF
