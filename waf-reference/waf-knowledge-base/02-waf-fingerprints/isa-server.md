---
id: WAF-FP-145
title: Isa Server WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Difficult
---

# Isa Server WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: 'The ISA Server denied the specified URL' | See detection details |

## Detailed Indicators

- Body: 'The ISA Server denied the specified URL'

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "isa-server"
```

## References

- https://github.com/0xInfection/Awesome-WAF
