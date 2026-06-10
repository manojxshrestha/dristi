---
id: WAF-FP-176
title: Safe3 WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Safe3 WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Powered-By: Safe3WAF | See detection details |
| Server: Safe3 Web Firewall | See detection details |

## Detailed Indicators

- X-Powered-By: Safe3WAF
- Server: Safe3 Web Firewall

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "safe3"
```

## References

- https://github.com/0xInfection/Awesome-WAF
