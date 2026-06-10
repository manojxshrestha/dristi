---
id: WAF-FP-199
title: Urlmaster Security WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Urlmaster Security WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| UrlMaster keyword | See detection details |
| UrlRewriteModule keyword | See detection details |
| SecurityCheck keyword | See detection details |

## Detailed Indicators

- UrlMaster keyword
- UrlRewriteModule keyword
- SecurityCheck keyword

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "urlmaster-security"
```

## References

- https://github.com/0xInfection/Awesome-WAF
