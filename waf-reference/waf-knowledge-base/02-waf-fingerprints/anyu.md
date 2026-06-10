---
id: WAF-FP-105
title: Anyu WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Anyu WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'intercepted by AnYu' | See detection details |
| Body: 'AnYu- the green channel' | See detection details |
| WZWS-RAY header | See detection details |

## Detailed Indicators

- Body: 'intercepted by AnYu'
- Body: 'AnYu- the green channel'
- WZWS-RAY header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "anyu"
```

## References

- https://github.com/0xInfection/Awesome-WAF
