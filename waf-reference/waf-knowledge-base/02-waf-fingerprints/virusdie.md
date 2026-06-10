---
id: WAF-FP-204
title: Virusdie WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Virusdie WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| virusdie.ru firewallstop.png | See detection details |
| FW_BLOCK meta tag | See detection details |

## Detailed Indicators

- virusdie.ru firewallstop.png
- FW_BLOCK meta tag

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "virusdie"
```

## References

- https://github.com/0xInfection/Awesome-WAF
