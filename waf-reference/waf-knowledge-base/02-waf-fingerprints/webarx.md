---
id: WAF-FP-209
title: Webarx WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Webarx WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'blocked by WebARX WAF' | See detection details |
| /wp-content/plugins/webarx/ | See detection details |

## Detailed Indicators

- Body: 'blocked by WebARX WAF'
- /wp-content/plugins/webarx/

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "webarx"
```

## References

- https://github.com/0xInfection/Awesome-WAF
