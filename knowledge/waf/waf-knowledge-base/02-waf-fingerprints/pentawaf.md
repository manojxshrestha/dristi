---
id: WAF-FP-164
title: Pentawaf WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Pentawaf WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: PentaWAF/{version} | See detection details |
| Body contains PentaWAF text | See detection details |

## Detailed Indicators

- Server: PentaWAF/{version}
- Body contains PentaWAF text

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "pentawaf"
```

## References

- https://github.com/0xInfection/Awesome-WAF
