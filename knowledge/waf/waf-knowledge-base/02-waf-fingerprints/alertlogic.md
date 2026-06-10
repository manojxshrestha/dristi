---
id: WAF-FP-103
title: Alertlogic WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Alertlogic WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Blocked page: 'We are sorry, but the page you are looking for cannot be found' | See detection details |
| 404 Not Found in red letters | See detection details |

## Detailed Indicators

- Blocked page: 'We are sorry, but the page you are looking for cannot be found'
- 404 Not Found in red letters

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "alertlogic"
```

## References

- https://github.com/0xInfection/Awesome-WAF
