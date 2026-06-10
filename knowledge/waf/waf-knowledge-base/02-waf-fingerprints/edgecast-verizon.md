---
id: WAF-FP-133
title: Edgecast Verizon WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Edgecast Verizon WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| 400 Bad Request on malicious input | See detection details |
| Contact site administrator message | See detection details |

## Detailed Indicators

- 400 Bad Request on malicious input
- Contact site administrator message

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "edgecast-verizon"
```

## References

- https://github.com/0xInfection/Awesome-WAF
