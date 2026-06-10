---
id: WAF-FP-186
title: Siteground WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Siteground WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'The page you are trying to access is restricted' | See detection details |

## Detailed Indicators

- Body: 'The page you are trying to access is restricted'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "siteground"
```

## References

- https://github.com/0xInfection/Awesome-WAF
