---
id: WAF-FP-210
title: Webray WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Webray WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: WebRay-WAF | See detection details |
| DrivedBy: RaySrv RayEng/{version} | See detection details |

## Detailed Indicators

- Server: WebRay-WAF
- DrivedBy: RaySrv RayEng/{version}

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "webray"
```

## References

- https://github.com/0xInfection/Awesome-WAF
