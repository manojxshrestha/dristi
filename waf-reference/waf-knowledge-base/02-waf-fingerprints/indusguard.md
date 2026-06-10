---
id: WAF-FP-143
title: Indusguard WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Indusguard WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: IF_WAF | See detection details |
| X-Version header | See detection details |

## Detailed Indicators

- Server: IF_WAF
- X-Version header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "indusguard"
```

## References

- https://github.com/0xInfection/Awesome-WAF
