---
id: WAF-FP-174
title: Rsfirewall WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Rsfirewall WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| COM_RSFIREWALL_403_FORBIDDEN | See detection details |
| COM_RSFIREWALL_EVENT | See detection details |

## Detailed Indicators

- COM_RSFIREWALL_403_FORBIDDEN
- COM_RSFIREWALL_EVENT

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "rsfirewall"
```

## References

- https://github.com/0xInfection/Awesome-WAF
