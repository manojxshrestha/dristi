---
id: WAF-FP-188
title: Sitelock WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Sitelock WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Reference to sitelock.com | See detection details |
| sitelock-site-verification | See detection details |

## Detailed Indicators

- Reference to sitelock.com
- sitelock-site-verification

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "sitelock"
```

## References

- https://github.com/0xInfection/Awesome-WAF
