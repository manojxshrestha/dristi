---
id: WAF-FP-009
title: Citrix NetScaler WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Citrix NetScaler WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `nnCoection:` (deliberately misspelled/jumbled) |
| Cookie | `ns_af=` |
| Cookie | `citrix_ns_id` |
| Cookie | `NSC_` prefix cookies |
| Response Body | "Access to this resource has been blocked by the NetScaler" |
| Response Body | "NetScaler" or "NS" in block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "netscaler\|ns_af\|citrix_ns\|nncoection"
```

## References
- https://www.citrix.com/products/citrix-web-app-firewall/
