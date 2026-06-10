---
id: WAF-FP-155
title: Netcontinuum WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Netcontinuum WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie: NCI__SessionId= | See detection details |

## Detailed Indicators

- Cookie: NCI__SessionId=

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "netcontinuum"
```

## References

- https://github.com/0xInfection/Awesome-WAF
