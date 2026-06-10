---
id: WAF-FP-187
title: Siteguard WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Siteguard WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Powered by SiteGuard' | See detection details |
| Body: 'The server refuse to browse the page' | See detection details |

## Detailed Indicators

- Body: 'Powered by SiteGuard'
- Body: 'The server refuse to browse the page'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "siteguard"
```

## References

- https://github.com/0xInfection/Awesome-WAF
