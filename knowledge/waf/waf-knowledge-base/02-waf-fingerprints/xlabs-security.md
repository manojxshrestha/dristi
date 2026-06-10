---
id: WAF-FP-214
title: Xlabs Security WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Xlabs Security WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-CDN: XLabs Security | See detection details |

## Detailed Indicators

- X-CDN: XLabs Security

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "xlabs-security"
```

## References

- https://github.com/0xInfection/Awesome-WAF
