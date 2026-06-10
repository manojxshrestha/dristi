---
id: WAF-FP-163
title: Openresty Lua WAF Fingerprint
category: WAF Fingerprints
severity_range: Informational
detectability: Easy
---

# Openresty Lua WAF Fingerprint

## Detection Methodology

| Indicator | Pattern |
|-----------|---------|
| Server: openresty/{version} | See detection details |
| Returns code 406 | See detection details |

## Detailed Indicators

- Server: openresty/{version}
- Returns code 406

## Example Detection Commands

```bash
curl -s -v https://target.com/ 2>&1 | grep -i "openresty-lua"
```

## References

- https://github.com/0xInfection/Awesome-WAF
