---
id: WAF-FP-208
title: Webtotem WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Webtotem WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'The current request was blocked by WebTotem' | See detection details |

## Detailed Indicators

- Body: 'The current request was blocked by WebTotem'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "webtotem"
```

## References

- https://github.com/0xInfection/Awesome-WAF
