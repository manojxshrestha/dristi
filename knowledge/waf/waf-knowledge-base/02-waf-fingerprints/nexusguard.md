---
id: WAF-FP-158
title: Nexusguard WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Nexusguard WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| speresources.nexusguard.com/wafpage reference | See detection details |

## Detailed Indicators

- speresources.nexusguard.com/wafpage reference

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "nexusguard"
```

## References

- https://github.com/0xInfection/Awesome-WAF
