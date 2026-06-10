---
id: WAF-FP-128
title: Crawlprotect WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Crawlprotect WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Cookie: crawlprotect | See detection details |
| Title: CrawlProtect | See detection details |

## Detailed Indicators

- Cookie: crawlprotect
- Title: CrawlProtect

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "crawlprotect"
```

## References

- https://github.com/0xInfection/Awesome-WAF
