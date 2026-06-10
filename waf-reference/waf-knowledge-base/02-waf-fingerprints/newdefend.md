---
id: WAF-FP-157
title: Newdefend WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Newdefend WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| newdefend.com/feedback reference | See detection details |
| /nd_block/ directory | See detection details |
| Server: NewDefend | See detection details |

## Detailed Indicators

- newdefend.com/feedback reference
- /nd_block/ directory
- Server: NewDefend

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "newdefend"
```

## References

- https://github.com/0xInfection/Awesome-WAF
