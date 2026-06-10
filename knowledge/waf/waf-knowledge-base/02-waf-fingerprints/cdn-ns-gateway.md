---
id: WAF-FP-120
title: Cdn Ns Gateway WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Cdn Ns Gateway WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'CdnNsWAF Application Gateway' | See detection details |

## Detailed Indicators

- Body: 'CdnNsWAF Application Gateway'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "cdn-ns-gateway"
```

## References

- https://github.com/0xInfection/Awesome-WAF
