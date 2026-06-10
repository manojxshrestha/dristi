---
id: WAF-FP-013
title: StackPath WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# StackPath WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: StackPath` |
| Response Body | "This request has been blocked by the StackPath" |
| Response Body | StackPath logo or branding in block page |
| Response Body | "triggered the service and blocked your request" |
| Response Code | 403 with StackPath block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "stackpath\|blocked by the stackpath"
```

## References
- https://www.stackpath.com/
