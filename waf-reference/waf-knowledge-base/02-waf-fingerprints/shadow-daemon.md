---
id: WAF-FP-184
title: Shadow Daemon WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Shadow Daemon WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'request forbidden by administrative rules' | See detection details |

## Detailed Indicators

- Body: 'request forbidden by administrative rules'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "shadow-daemon"
```

## References

- https://github.com/0xInfection/Awesome-WAF
