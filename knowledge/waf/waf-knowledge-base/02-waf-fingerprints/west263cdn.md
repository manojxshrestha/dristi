---
id: WAF-FP-212
title: West263Cdn WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# West263Cdn WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Cache: WT263CDN | See detection details |

## Detailed Indicators

- X-Cache: WT263CDN

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "west263cdn"
```

## References

- https://github.com/0xInfection/Awesome-WAF
