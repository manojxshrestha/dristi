---
id: WAF-FP-198
title: Ucloud Uewaf WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Ucloud Uewaf WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| /uewaf_deny_pages/ reference | See detection details |
| Server: uewaf/{version} | See detection details |

## Detailed Indicators

- /uewaf_deny_pages/ reference
- Server: uewaf/{version}

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "ucloud-uewaf"
```

## References

- https://github.com/0xInfection/Awesome-WAF
