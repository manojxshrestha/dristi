---
id: WAF-FP-194
title: Tencent Cloud WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Tencent Cloud WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Code 405 | See detection details |
| Reference to waf.tencent-cloud.com | See detection details |

## Detailed Indicators

- Code 405
- Reference to waf.tencent-cloud.com

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "tencent-cloud"
```

## References

- https://github.com/0xInfection/Awesome-WAF
