---
id: WAF-FP-110
title: Aspnet Generic WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Aspnet Generic WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-ASPNET-Version header | See detection details |
| Generic 403 error for unauthorized users | See detection details |

## Detailed Indicators

- X-ASPNET-Version header
- Generic 403 error for unauthorized users

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "aspnet-generic"
```

## References

- https://github.com/0xInfection/Awesome-WAF
