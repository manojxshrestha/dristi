---
id: WAF-FP-112
title: Baidu Yunjiasu WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Baidu Yunjiasu WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: Yunjiasu-nginx | See detection details |

## Detailed Indicators

- Server: Yunjiasu-nginx

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "baidu-yunjiasu"
```

## References

- https://github.com/0xInfection/Awesome-WAF
