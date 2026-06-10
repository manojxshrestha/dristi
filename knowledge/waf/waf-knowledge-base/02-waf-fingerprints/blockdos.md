---
id: WAF-FP-117
title: Blockdos WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Moderate
---

# Blockdos WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: BlockDos.net | See detection details |

## Detailed Indicators

- Server: BlockDos.net

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "blockdos"
```

## References

- https://github.com/0xInfection/Awesome-WAF
