---
id: WAF-FP-149
title: Knownsec WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Knownsec WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| ks-waf-error.png image in block page | See detection details |

## Detailed Indicators

- ks-waf-error.png image in block page

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "knownsec"
```

## References

- https://github.com/0xInfection/Awesome-WAF
