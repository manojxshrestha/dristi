---
id: WAF-FP-104
title: Aliyundun WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Aliyundun WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Blocked page references errors.aliyun.com | See detection details |
| Returns code 405 | See detection details |
| Server: aliyundun | See detection details |

## Detailed Indicators

- Blocked page references errors.aliyun.com
- Returns code 405
- Server: aliyundun

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "aliyundun"
```

## References

- https://github.com/0xInfection/Awesome-WAF
