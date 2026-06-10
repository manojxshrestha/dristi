---
id: WAF-FP-125
title: Cloudbric WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Cloudbric WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Malicious Code Detected' | See detection details |
| Body: 'blocked by Cloudbric' | See detection details |

## Detailed Indicators

- Body: 'Malicious Code Detected'
- Body: 'blocked by Cloudbric'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "cloudbric"
```

## References

- https://github.com/0xInfection/Awesome-WAF
