---
id: WAF-FP-171
title: Qiniu Cdn WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Qiniu Cdn WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Qiniu-CDN header set to 0 or 1 | See detection details |

## Detailed Indicators

- X-Qiniu-CDN header set to 0 or 1

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "qiniu-cdn"
```

## References

- https://github.com/0xInfection/Awesome-WAF
