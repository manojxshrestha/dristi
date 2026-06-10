---
id: WAF-FP-116
title: Bitninja WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Bitninja WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Security check by BitNinja' | See detection details |
| reCAPTCHA challenge | See detection details |

## Detailed Indicators

- Body: 'Security check by BitNinja'
- reCAPTCHA challenge

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "bitninja"
```

## References

- https://github.com/0xInfection/Awesome-WAF
