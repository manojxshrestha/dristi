---
id: WAF-FP-132
title: E3Learning WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# E3Learning WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: e3Learning_WAF | See detection details |

## Detailed Indicators

- Server: e3Learning_WAF

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "e3learning"
```

## References

- https://github.com/0xInfection/Awesome-WAF
