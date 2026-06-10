---
id: WAF-FP-159
title: Ninjafirewall WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Ninjafirewall WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Title: 'NinjaFirewall: 403 Forbidden' | See detection details |
| Body: 'For security reasons' | See detection details |

## Detailed Indicators

- Title: 'NinjaFirewall: 403 Forbidden'
- Body: 'For security reasons'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "ninjafirewall"
```

## References

- https://github.com/0xInfection/Awesome-WAF
