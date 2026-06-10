---
id: WAF-FP-218
title: Yxlink WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Yxlink WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| yx_ci_session cookie | See detection details |
| yx_language cookie | See detection details |
| Server: Yxlink-WAF | See detection details |

## Detailed Indicators

- yx_ci_session cookie
- yx_language cookie
- Server: Yxlink-WAF

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "yxlink"
```

## References

- https://github.com/0xInfection/Awesome-WAF
