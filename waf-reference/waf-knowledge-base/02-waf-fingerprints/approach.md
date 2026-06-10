---
id: WAF-FP-106
title: Approach WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Approach WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Approach Web Application Firewall Framework' | See detection details |
| Your IP has been logged warning | See detection details |
| Server: Approach | See detection details |

## Detailed Indicators

- Body: 'Approach Web Application Firewall Framework'
- Your IP has been logged warning
- Server: Approach

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "approach"
```

## References

- https://github.com/0xInfection/Awesome-WAF
