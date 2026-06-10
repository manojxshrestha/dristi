---
id: WAF-FP-183
title: Serverdefender Vp WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Serverdefender Vp WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Pint: p80 header | See detection details |

## Detailed Indicators

- X-Pint: p80 header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "serverdefender-vp"
```

## References

- https://github.com/0xInfection/Awesome-WAF
