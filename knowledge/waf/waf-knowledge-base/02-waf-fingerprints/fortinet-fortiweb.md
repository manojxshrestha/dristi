---
id: WAF-FP-008
title: Fortinet FortiWeb WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Fortinet FortiWeb WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie | `FORTIWAFSID=` |
| Response Body | `.fgd_icon` (FortiGuard icon reference) |
| Response Body | "Server Unavailable!" |
| Response Code | 503 with FortiWeb block page |
| Header | `Server: FortiWeb` or `Server: Fortinet` |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "fortiweb\|fortiwafsid\|fgd_icon"
```

## References
- https://www.fortinet.com/products/web-application-firewall/fortiweb
