---
id: WAF-FP-196
title: Trafficshield WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Trafficshield WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: F5-TrafficShield | See detection details |
| ASINFO= cookie | See detection details |

## Detailed Indicators

- Server: F5-TrafficShield
- ASINFO= cookie

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "trafficshield"
```

## References

- https://github.com/0xInfection/Awesome-WAF
