---
id: WAF-FP-201
title: Varnish Cachewall WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Varnish Cachewall WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Error 403 Naughty, not Nice!' | See detection details |
| Varnish cache Server | See detection details |

## Detailed Indicators

- Body: 'Error 403 Naughty, not Nice!'
- Varnish cache Server

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "varnish-cachewall"
```

## References

- https://github.com/0xInfection/Awesome-WAF
