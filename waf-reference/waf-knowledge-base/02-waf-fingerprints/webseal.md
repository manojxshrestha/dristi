---
id: WAF-FP-211
title: Webseal WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Webseal WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: WebSEAL | See detection details |
| Body: 'This is a WebSEAL error message template file' | See detection details |

## Detailed Indicators

- Server: WebSEAL
- Body: 'This is a WebSEAL error message template file'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "webseal"
```

## References

- https://github.com/0xInfection/Awesome-WAF
