---
id: WAF-FP-023
title: SonicWall WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# SonicWall WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: SonicWALL` |
| Response Body | "This request is blocked by the SonicWALL" |
| Response Body | "SonicWall" branding in block page |
| Response Code | 403 with SonicWall block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "sonicwall\|sonic_wall"
```

## References
- https://www.sonicwall.com/products/web-application-firewall/
