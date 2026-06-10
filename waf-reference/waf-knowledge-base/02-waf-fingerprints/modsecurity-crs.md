---
id: WAF-FP-153
title: Modsecurity Crs WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Modsecurity Crs WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Scanner header triggers block at specific paranoia levels | See detection details |

## Detailed Indicators

- X-Scanner header triggers block at specific paranoia levels

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "modsecurity-crs"
```

## References

- https://github.com/0xInfection/Awesome-WAF
