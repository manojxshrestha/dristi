---
id: WAF-FP-111
title: Astra WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Astra WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Sorry, this is not allowed.' | See detection details |
| getastra.com/assets/images/ reference | See detection details |
| cz_astra_csrf_cookie | See detection details |

## Detailed Indicators

- Body: 'Sorry, this is not allowed.'
- getastra.com/assets/images/ reference
- cz_astra_csrf_cookie

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "astra"
```

## References

- https://github.com/0xInfection/Awesome-WAF
