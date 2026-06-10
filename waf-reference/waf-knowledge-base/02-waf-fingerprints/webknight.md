---
id: WAF-FP-015
title: WebKnight WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# WebKnight WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Header | `WebKnight` in response headers |
| Response Body | "WebKnight Application Firewall Alert" |
| Response Code | 999 (WebKnight specific status code) or 404 |
| Response Body | "This request has been blocked by WebKnight" |

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "webknight"
```

## References
- https://www.aqtronix.com/WebKnight/
