---
id: WAF-FP-205
title: Wallarm WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Wallarm WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: nginx-wallarm | See detection details |

## Detailed Indicators

- Server: nginx-wallarm

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "wallarm"
```

## References

- https://github.com/0xInfection/Awesome-WAF
