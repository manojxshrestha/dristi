---
id: WAF-FP-191
title: Squidproxy Ids WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Squidproxy Ids WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: squid/{version} | See detection details |
| Access control configuration prevents | See detection details |

## Detailed Indicators

- Server: squid/{version}
- Access control configuration prevents

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "squidproxy-ids"
```

## References

- https://github.com/0xInfection/Awesome-WAF
