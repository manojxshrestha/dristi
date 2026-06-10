---
id: WAF-FP-203
title: Viettel WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Viettel WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Title: 'Access denied - Viettel WAF' | See detection details |
| cloudrity.com.vn reference | See detection details |

## Detailed Indicators

- Title: 'Access denied - Viettel WAF'
- cloudrity.com.vn reference

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "viettel"
```

## References

- https://github.com/0xInfection/Awesome-WAF
