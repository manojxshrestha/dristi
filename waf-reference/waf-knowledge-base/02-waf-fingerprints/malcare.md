---
id: WAF-FP-151
title: Malcare WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Malcare WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'Blocked because of Malicious Activities' | See detection details |
| Body: 'Firewall powered by MalCare' | See detection details |

## Detailed Indicators

- Body: 'Blocked because of Malicious Activities'
- Body: 'Firewall powered by MalCare'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "malcare"
```

## References

- https://github.com/0xInfection/Awesome-WAF
