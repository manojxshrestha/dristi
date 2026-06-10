---
id: WAF-FP-166
title: Pksecurity Module WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Pksecurity Module WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'pkSecurityModule: Security.Alert' | See detection details |

## Detailed Indicators

- Body: 'pkSecurityModule: Security.Alert'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "pksecurity-module"
```

## References

- https://github.com/0xInfection/Awesome-WAF
