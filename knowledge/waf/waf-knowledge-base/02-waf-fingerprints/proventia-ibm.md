---
id: WAF-FP-169
title: Proventia Ibm WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Proventia Ibm WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'request does not match Proventia rules' | See detection details |

## Detailed Indicators

- Body: 'request does not match Proventia rules'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "proventia-ibm"
```

## References

- https://github.com/0xInfection/Awesome-WAF
