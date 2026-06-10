---
id: WAF-FP-197
title: Transip WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Transip WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-TransIP-Backend header | See detection details |
| X-TransIP-Balancer header | See detection details |

## Detailed Indicators

- X-TransIP-Backend header
- X-TransIP-Balancer header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "transip"
```

## References

- https://github.com/0xInfection/Awesome-WAF
