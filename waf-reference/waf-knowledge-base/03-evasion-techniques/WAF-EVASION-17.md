---
id: WAF-EVASION-17
title: SSL/TLS Cipher Abuse
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-17: SSL/TLS Cipher Abuse

## Summary

Some WAFs only inspect traffic encrypted with specific SSL/TLS cipher suites. By selecting ciphers that the WAF does not inspect, attackers can bypass WAF detection entirely.

## When to Use

- When the WAF is deployed as a reverse proxy with SSL termination
- Against cloud WAFs that decrypt and re-encrypt traffic
- For evading WAFs with selective cipher inspection

## Technique

1. Identify cipher suites supported by the target
2. Test which ciphers trigger WAF inspection (send malicious payload)
3. Use ciphers that bypass inspection

## Tool

```bash
# abuse-ssl-bypass-waf tool
git clone https://github.com/abuse-ssl-bypass-waf
```

## Payload Example

```bash
curl --ciphers 'ECDHE-RSA-AES128-GCM-SHA256' -k https://target.com/?q=<script>alert(1)</script>
```

## References

- abuse-ssl-bypass-waf repository
