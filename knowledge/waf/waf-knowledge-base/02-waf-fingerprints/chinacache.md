---
id: WAF-FP-123
title: Chinacache WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Chinacache WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Headers: Powered-by-ChinaCache | See detection details |

## Detailed Indicators

- Headers: Powered-by-ChinaCache

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "chinacache"
```

## References

- https://github.com/0xInfection/Awesome-WAF
