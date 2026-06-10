---
id: WAF-FP-152
title: Missioncontrol WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Missioncontrol WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: Mission Control Application Shield | See detection details |

## Detailed Indicators

- Server: Mission Control Application Shield

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "missioncontrol"
```

## References

- https://github.com/0xInfection/Awesome-WAF
