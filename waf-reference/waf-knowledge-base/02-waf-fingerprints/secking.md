---
id: WAF-FP-177
title: Secking WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy/Moderate
---

# Secking WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: SECKINGWAF | See detection details |
| Server: SECKING/{version} | See detection details |

## Detailed Indicators

- Server: SECKINGWAF
- Server: SECKING/{version}

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "secking"
```

## References

- https://github.com/0xInfection/Awesome-WAF
