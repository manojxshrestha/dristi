---
id: WAF-FP-018
title: UrlScan WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# UrlScan WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `Rejected-By-UrlScan` |
| Response Body | "Server Error in Application" |
| Header | `Server: Microsoft-IIS` (UrlScan runs as IIS extension) |
| Response Code | 404 (UrlScan rejects with 404 instead of 403) |
| Response Body | "UrlScan" in error page |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "urlscan\|rejected-by-urlscan"
```

## References
- https://learn.microsoft.com/en-us/iis/extensions/working-with-url-scan/urlscan-3-reference
