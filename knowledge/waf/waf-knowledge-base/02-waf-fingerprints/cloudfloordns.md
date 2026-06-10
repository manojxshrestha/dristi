---
id: WAF-FP-126
title: Cloudfloordns WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Cloudfloordns WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: CloudfloorDNS WAF | See detection details |
| Title: CloudfloorDNS - Web Application Firewall Error | See detection details |

## Detailed Indicators

- Server: CloudfloorDNS WAF
- Title: CloudfloorDNS - Web Application Firewall Error

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "cloudfloordns"
```

## References

- https://github.com/0xInfection/Awesome-WAF
