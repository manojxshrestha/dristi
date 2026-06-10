---
id: WAF-FP-005
title: F5 BIG-IP ASM WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# F5 BIG-IP ASM WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie | `BigIP` or `BIGipServer` |
| Header | `X-WA-Info` |
| Header Jumbling | Headers may appear in unusual order |
| Response Code | 403 with "The requested URL was rejected" |
| Response Body | "Please consult with your administrator" |
| Header | `Server: BIG-IP` or `Server: F5` |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "bigip\|big-ip\|x-wa-info"
```

## References
- https://www.f5.com/products/security/advanced-web-application-firewall
