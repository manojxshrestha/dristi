---
id: WAF-FP-148
title: Keycdn WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Keycdn WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: KeyCDN | See detection details |

## Detailed Indicators

- Server: KeyCDN

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "keycdn"
```

## References

- https://github.com/0xInfection/Awesome-WAF
