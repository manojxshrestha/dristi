---
id: WAF-FP-147
title: Jiasule WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Jiasule WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| static.jiasule.com JS reference | See detection details |
| __jsluid= cookie | See detection details |
| Server: jiasule-WAF | See detection details |

## Detailed Indicators

- static.jiasule.com JS reference
- __jsluid= cookie
- Server: jiasule-WAF

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "jiasule"
```

## References

- https://github.com/0xInfection/Awesome-WAF
