---
id: WAF-FP-017
title: Palo Alto Networks WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Palo Alto Networks WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Response Body | "Virus/Spyware Download Blocked" |
| Response Body | "Palo Alto Next Generation Security Platform" |
| Response Body | "Blocked by PAN" or "Palo Alto Networks" |
| Response Code | 403 with Palo Alto block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "palo alto\|virus/spyware download blocked\|blocked by pan"
```

## References
- https://www.paloaltonetworks.com/network-security/web-application-firewall
