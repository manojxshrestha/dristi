---
id: WAF-FP-175
title: Sabre WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Sabre WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Code 500 on malicious requests | See detection details |
| Contact dxsupport@sabre.com | See detection details |

## Detailed Indicators

- Code 500 on malicious requests
- Contact dxsupport@sabre.com

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "sabre"
```

## References

- https://github.com/0xInfection/Awesome-WAF
