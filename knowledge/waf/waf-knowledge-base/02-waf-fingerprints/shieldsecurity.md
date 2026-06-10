---
id: WAF-FP-185
title: Shieldsecurity WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Shieldsecurity WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'You were blocked by the Shield' | See detection details |
| Transgression warning | See detection details |

## Detailed Indicators

- Body: 'You were blocked by the Shield'
- Transgression warning

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "shieldsecurity"
```

## References

- https://github.com/0xInfection/Awesome-WAF
