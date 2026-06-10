---
id: WAF-FP-138
title: Greywizard WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Greywizard WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Grey Wizard' text | See detection details |
| Server: greywizard | See detection details |

## Detailed Indicators

- Body: 'Grey Wizard' text
- Server: greywizard

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "greywizard"
```

## References

- https://github.com/0xInfection/Awesome-WAF
