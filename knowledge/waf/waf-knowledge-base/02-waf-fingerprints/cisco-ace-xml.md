---
id: WAF-FP-124
title: Cisco Ace Xml WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Cisco Ace Xml WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: ACE XML Gateway | See detection details |

## Detailed Indicators

- Server: ACE XML Gateway

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "cisco-ace-xml"
```

## References

- https://github.com/0xInfection/Awesome-WAF
