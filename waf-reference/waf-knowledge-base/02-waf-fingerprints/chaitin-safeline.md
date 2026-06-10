---
id: WAF-FP-122
title: Chaitin Safeline WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Chaitin Safeline WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body contains event_id in HTML comments | See detection details |

## Detailed Indicators

- Body contains event_id in HTML comments

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "chaitin-safeline"
```

## References

- https://github.com/0xInfection/Awesome-WAF
