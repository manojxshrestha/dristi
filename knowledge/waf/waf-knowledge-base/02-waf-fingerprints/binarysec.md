---
id: WAF-FP-115
title: Binarysec WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Binarysec WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-BinarySec-Via header | See detection details |
| X-BinarySec-NoCache header | See detection details |

## Detailed Indicators

- X-BinarySec-Via header
- X-BinarySec-NoCache header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "binarysec"
```

## References

- https://github.com/0xInfection/Awesome-WAF
