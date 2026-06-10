---
id: WAF-FP-024
title: ZScaler WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# ZScaler WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: ZScaler` |
| Response Body | "Access Denied: Accenture Policy" or similar policy message |
| Response Body | "ZScaler" branding in block page |
| Response Body | "zscloud.net" references in block page |
| Response Code | 403 with ZScaler block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "zscaler\|zscloud\|access denied"
```

## References
- https://www.zscaler.com/products/zscaler-internet-access
