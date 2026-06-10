---
id: WAF-FP-137
title: Godaddy WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Godaddy WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Access Denied - GoDaddy Website Firewall' | See detection details |

## Detailed Indicators

- Body: 'Access Denied - GoDaddy Website Firewall'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "godaddy"
```

## References

- https://github.com/0xInfection/Awesome-WAF
