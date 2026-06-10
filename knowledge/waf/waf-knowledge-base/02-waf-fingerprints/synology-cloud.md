---
id: WAF-FP-193
title: Synology Cloud WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Synology Cloud WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Copyright (c) 2019 Synology Inc. | See detection details |

## Detailed Indicators

- Copyright (c) 2019 Synology Inc.

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "synology-cloud"
```

## References

- https://github.com/0xInfection/Awesome-WAF
