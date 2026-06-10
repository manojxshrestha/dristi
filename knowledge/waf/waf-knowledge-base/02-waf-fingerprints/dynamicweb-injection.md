---
id: WAF-FP-131
title: Dynamicweb Injection WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Dynamicweb Injection WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-403-Status-By: dw-inj-check | See detection details |

## Detailed Indicators

- X-403-Status-By: dw-inj-check

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "dynamicweb-injection"
```

## References

- https://github.com/0xInfection/Awesome-WAF
