---
id: WAF-EVASION-19
title: DNS History Abuse
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-19: DNS History Abuse

## Summary

WAFs protect specific IP addresses (the origin server). If an attacker can find the origin server's historical IP addresses that are no longer behind the WAF, they can bypass the WAF entirely by connecting directly to the origin.

## When to Use

- When the WAF is deployed as a reverse proxy
- For cloud WAFs (Cloudflare, Sucuri, etc.)
- When direct origin access would bypass all WAF rules

## Technique

1. Query historical DNS records for the target domain
2. Find IP addresses that previously hosted the application
3. Test if these IPs still serve the application (without WAF)
4. Directly attack the origin IP

## Tools

```bash
# bypass-firewalls-by-DNS-history
git clone https://github.com/vincentcox/bypass-firewalls-by-DNS-history
cd bypass-firewalls-by-DNS-history
python3 bypass-firewalls-by-DNS-history.py -d target.com
```

## DNS History Services

- **IP History** - Historical IP address lookup
- **DNS Trails** - DNS record history
- **SecurityTrails** - API-based historical DNS
- **CriminalIP** - Historical IP data

## References

- https://github.com/vincentcox/bypass-firewalls-by-DNS-history
