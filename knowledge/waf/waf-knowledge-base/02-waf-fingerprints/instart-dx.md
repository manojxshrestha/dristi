---
id: WAF-FP-144
title: Instart Dx WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Instart Dx WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Instart-Request-ID header | See detection details |
| X-Instart-WL header | See detection details |
| X-Instart-Cache header | See detection details |

## Detailed Indicators

- X-Instart-Request-ID header
- X-Instart-WL header
- X-Instart-Cache header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "instart-dx"
```

## References

- https://github.com/0xInfection/Awesome-WAF
