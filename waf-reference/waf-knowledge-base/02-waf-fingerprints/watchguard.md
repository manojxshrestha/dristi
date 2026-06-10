---
id: WAF-FP-206
title: Watchguard WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Watchguard WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: WatchGuard | See detection details |
| Body: 'Request denied by WatchGuard Firewall' | See detection details |

## Detailed Indicators

- Server: WatchGuard
- Body: 'Request denied by WatchGuard Firewall'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "watchguard"
```

## References

- https://github.com/0xInfection/Awesome-WAF
