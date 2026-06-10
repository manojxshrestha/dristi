---
id: WAF-FP-172
title: Reblaze WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Reblaze WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie: rbzid= | See detection details |
| Server: Reblaze Secure Web Gateway | See detection details |

## Detailed Indicators

- Cookie: rbzid=
- Server: Reblaze Secure Web Gateway

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "reblaze"
```

## References

- https://github.com/0xInfection/Awesome-WAF
