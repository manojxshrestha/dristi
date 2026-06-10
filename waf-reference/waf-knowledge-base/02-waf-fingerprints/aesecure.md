---
id: WAF-FP-101
title: Aesecure WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Aesecure WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Blocked content contains aesecure_denied.png | See detection details |
| Response headers contain aeSecure-code | See detection details |

## Detailed Indicators

- Blocked content contains aesecure_denied.png
- Response headers contain aeSecure-code

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "aesecure"
```

## References

- https://github.com/0xInfection/Awesome-WAF
