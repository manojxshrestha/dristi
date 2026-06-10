---
id: WAF-FP-109
title: Aspa WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Aspa WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: ASPA-WAF | See detection details |
| ASPA-Cache-Status header | See detection details |

## Detailed Indicators

- Server: ASPA-WAF
- ASPA-Cache-Status header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "aspa"
```

## References

- https://github.com/0xInfection/Awesome-WAF
