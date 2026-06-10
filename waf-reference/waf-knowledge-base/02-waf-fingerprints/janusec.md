---
id: WAF-FP-146
title: Janusec WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Janusec WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body displays JANUSEC name and logo | See detection details |

## Detailed Indicators

- Body displays JANUSEC name and logo

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "janusec"
```

## References

- https://github.com/0xInfection/Awesome-WAF
