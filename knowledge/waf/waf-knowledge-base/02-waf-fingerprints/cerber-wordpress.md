---
id: WAF-FP-121
title: Cerber Wordpress WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Cerber Wordpress WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Your request looks suspicious' | See detection details |
| WordPress plugin | See detection details |

## Detailed Indicators

- Body: 'Your request looks suspicious'
- WordPress plugin

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "cerber-wordpress"
```

## References

- https://github.com/0xInfection/Awesome-WAF
