---
id: WAF-FP-006
title: Sucuri CloudProxy WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Sucuri CloudProxy WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: Sucuri` or `Server: Cloudproxy` |
| Header | `X-Sucuri-ID` |
| Response Body | "Access Denied - Sucuri Website Firewall" |
| Response Body | "Sucuri WebSite Firewall - CloudProxy - Access Denied" |
| Response Code | 403 with Sucuri branding |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "sucuri\|cloudproxy\|x-sucuri"
```

## References
- https://sucuri.net/website-firewall/
