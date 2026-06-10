---
id: WAF-FP-202
title: Varnish Owasp WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Varnish Owasp WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Code 404 on malicious requests | See detection details |
| Body: 'Request rejected by xVarnish-WAF' | See detection details |

## Detailed Indicators

- Code 404 on malicious requests
- Body: 'Request rejected by xVarnish-WAF'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "varnish-owasp"
```

## References

- https://github.com/0xInfection/Awesome-WAF
