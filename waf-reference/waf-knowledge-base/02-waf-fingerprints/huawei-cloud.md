---
id: WAF-FP-139
title: Huawei Cloud WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Huawei Cloud WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Error image from hwclouds.com/static/error/images/ | See detection details |

## Detailed Indicators

- Error image from hwclouds.com/static/error/images/

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "huawei-cloud"
```

## References

- https://github.com/0xInfection/Awesome-WAF
