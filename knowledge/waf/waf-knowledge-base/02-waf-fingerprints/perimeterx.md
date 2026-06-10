---
id: WAF-FP-165
title: Perimeterx WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Perimeterx WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| perimeterx.com/whywasiblocked reference | See detection details |

## Detailed Indicators

- perimeterx.com/whywasiblocked reference

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "perimeterx"
```

## References

- https://github.com/0xInfection/Awesome-WAF
