---
id: WAF-FP-134
title: Eisoo Cloud WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Eisoo Cloud WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| /eisoo-firewall-block.css reference | See detection details |
| Server: EisooWAF | See detection details |

## Detailed Indicators

- /eisoo-firewall-block.css reference
- Server: EisooWAF

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "eisoo-cloud"
```

## References

- https://github.com/0xInfection/Awesome-WAF
