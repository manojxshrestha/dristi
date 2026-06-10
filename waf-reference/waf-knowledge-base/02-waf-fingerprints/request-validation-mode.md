---
id: WAF-FP-173
title: Request Validation Mode WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Request Validation Mode WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| ASP.NET: 'potentially dangerous request detected' | See detection details |
| Code 500 | See detection details |

## Detailed Indicators

- ASP.NET: 'potentially dangerous request detected'
- Code 500

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "request-validation-m"
```

## References

- https://github.com/0xInfection/Awesome-WAF
