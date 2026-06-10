---
id: WAF-FP-001
title: Cloudflare WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Cloudflare WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie | `__cfuid=` |
| Header | `Server: cloudflare` |
| Header | `cf-ray` (e.g., `cf-ray: 123abc456`) |
| Response Code | 403 with "Attention Required! | Cloudflare" |
| Response Body | "Attention Required!" or "Please complete the security check to access" |
| Response Body | Cloudflare challenge page (JavaScript challenge or CAPTCHA) |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "cf-ray\|cloudflare\|__cfuid"
```

## References
- https://www.cloudflare.com/waf/
