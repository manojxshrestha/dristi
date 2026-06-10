---
id: WAF-FP-213
title: Wts Waf WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Wts Waf WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Title: WTS-WAF | See detection details |
| Server: wts | See detection details |

## Detailed Indicators

- Title: WTS-WAF
- Server: wts

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "wts-waf"
```

## References

- https://github.com/0xInfection/Awesome-WAF
