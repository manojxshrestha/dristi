---
id: WAF-FP-010
title: Akamai Kona WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Akamai Kona WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Server: AkamaiGHost` |
| Header | `X-Akamai-*` custom headers (e.g., `X-Akamai-Request-ID`) |
| Header | `X-True-Cache-Key` |
| Response Body | "Reference #" followed by numeric reference number |
| Response Code | 403 with Akamai block page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "akamai\|x-akamai\|akamaighost"
```

## References
- https://www.akamai.com/products/kona-site-defender
