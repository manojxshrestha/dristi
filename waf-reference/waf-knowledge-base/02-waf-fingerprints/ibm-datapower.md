---
id: WAF-FP-141
title: Ibm Datapower WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Ibm Datapower WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| X-Backside-Transport: OK/FAIL header | See detection details |

## Detailed Indicators

- X-Backside-Transport: OK/FAIL header

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "ibm-datapower"
```

## References

- https://github.com/0xInfection/Awesome-WAF
