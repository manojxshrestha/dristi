---
id: WAF-FP-170
title: Puhui WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Puhui WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: PuhuiWAF | See detection details |

## Detailed Indicators

- Server: PuhuiWAF

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "puhui"
```

## References

- https://github.com/0xInfection/Awesome-WAF
