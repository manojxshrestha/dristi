---
id: WAF-FP-182
title: Senginx WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Senginx WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Body: SENGINX-ROBOT-MITIGATION | See detection details |

## Detailed Indicators

- Body: SENGINX-ROBOT-MITIGATION

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "senginx"
```

## References

- https://github.com/0xInfection/Awesome-WAF
