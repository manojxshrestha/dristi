---
id: WAF-FP-154
title: Nemesida WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Nemesida WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Suspicious activity detected' | See detection details |
| Contact nwaf@{site.tld} | See detection details |

## Detailed Indicators

- Body: 'Suspicious activity detected'
- Contact nwaf@{site.tld}

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "nemesida"
```

## References

- https://github.com/0xInfection/Awesome-WAF
