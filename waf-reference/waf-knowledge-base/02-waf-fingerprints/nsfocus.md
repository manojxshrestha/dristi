---
id: WAF-FP-160
title: Nsfocus WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Nsfocus WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: NSFocus | See detection details |

## Detailed Indicators

- Server: NSFocus

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "nsfocus"
```

## References

- https://github.com/0xInfection/Awesome-WAF
