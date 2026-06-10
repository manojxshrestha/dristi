---
id: WAF-FP-217
title: Yunsuo WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Yunsuo WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| yunsuologo image class | See detection details |
| yunsuo_session cookie | See detection details |

## Detailed Indicators

- yunsuologo image class
- yunsuo_session cookie

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "yunsuo"
```

## References

- https://github.com/0xInfection/Awesome-WAF
