---
id: WAF-FP-102
title: Airlock WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate/Difficult
---

# Airlock WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Set-Cookie: AL-SESS | See detection details |
| Set-Cookie: AL-LB | See detection details |
| Blocked page: 'Server detected a syntax error' | See detection details |

## Detailed Indicators

- Set-Cookie: AL-SESS
- Set-Cookie: AL-LB
- Blocked page: 'Server detected a syntax error'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "airlock"
```

## References

- https://github.com/0xInfection/Awesome-WAF
