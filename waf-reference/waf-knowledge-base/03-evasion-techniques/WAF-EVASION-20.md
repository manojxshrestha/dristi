---
id: WAF-EVASION-20
title: Whitelist String Abuse
category: Evasion Techniques
severity_range: Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-20: Whitelist String Abuse

## Summary

Many WAFs implement whitelists for specific strings, paths, or parameters that bypass all security checks. If an attacker discovers a whitelisted value, they can inject it into their requests to bypass the WAF entirely.

## When to Use

- Against WAFs with shared-secret or internal-use whitelists
- When testing WordPress plugins with WAF functionality
- When internal documentation reveals whitelist entries

## Technique

1. Discover whitelist entries through:
   - Reverse engineering WAF client-side code
   - Reading documentation or source code
   - Fuzzing for accepted parameters
   - Analyzing WAF block pages for hints
2. Inject whitelist strings into requests
3. WAF permits the request without inspection

## Common Whitelist Vectors

- **Shared secret parameters**: `?secret=value` or `?bypass=1`
- **Internal paths**: `/admin/`, `/internal/`, `/healthcheck`
- **User-Agent strings**: Specific internal user agents
- **Cookies**: Internal session cookies

## Payload Example

```
GET /?id=1'+OR+'1'='1&internal=true HTTP/1.1
Host: target.com
X-Internal: true
```

## References

- WebARX whitelist bypass case
