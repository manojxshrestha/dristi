---
id: WAF-FP-180
title: Secureiis WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Secureiis WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| BeyondTrust logo | See detection details |
| Body: 'Download SecureIIS Personal Edition' | See detection details |

## Detailed Indicators

- BeyondTrust logo
- Body: 'Download SecureIIS Personal Edition'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "secureiis"
```

## References

- https://github.com/0xInfection/Awesome-WAF
