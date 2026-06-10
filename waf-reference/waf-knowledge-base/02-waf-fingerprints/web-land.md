---
id: WAF-FP-207
title: Web Land WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Web Land WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: Apache Protected By WebLand WAF | See detection details |

## Detailed Indicators

- Server: Apache Protected By WebLand WAF

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "web-land"
```

## References

- https://github.com/0xInfection/Awesome-WAF
