---
id: WAF-FP-012
title: Comodo cWatch WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Comodo cWatch WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: Protected by COMODO WAF` |
| Response Body | "Protected by COMODO" in block page |
| Response Body | "cWatch" branding |
| Cookie | `comodo_` prefix cookies |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "comodo\|cwatch\|protected by comodo"
```

## References
- https://www.comodo.com/cwatch/
