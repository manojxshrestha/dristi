---
id: WAF-FP-178
title: Secupress WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Secupress WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'SecuPress' | See detection details |
| Block ID: Bad URL Contents | See detection details |

## Detailed Indicators

- Body: 'SecuPress'
- Block ID: Bad URL Contents

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "secupress"
```

## References

- https://github.com/0xInfection/Awesome-WAF
