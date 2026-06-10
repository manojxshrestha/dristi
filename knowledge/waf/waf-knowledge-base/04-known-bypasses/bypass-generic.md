---
id: WAF-BYPASS-014
title: Generic WAF Bypass Techniques
category: Known Bypasses
severity_range: Medium-Critical
---

# Generic WAF Bypass Techniques

## Apache Generic - Lowercase HTTP Method

Sending HTTP methods in lowercase can bypass Apache-based WAFs:
```
get / HTTP/1.1
```

## IIS Generic - Tab Before Method

Inserting a tab character before the HTTP method:
```
\tGET / HTTP/1.1
```

## Other Generic Techniques

1. **Non-standard HTTP methods**: Using OPTIONS, TRACE, or custom methods
2. **HTTP/0.9 requests**: Minimal requests without headers
3. **Transfer-Encoding manipulation**: Chunked encoding abuse
4. **Content-Type variations**: Using non-standard content types
5. **Multipart boundary manipulation**: Breaking payloads across boundaries
6. **HTTP/2 downgrade**: Exploiting differences between HTTP/2 and HTTP/1.1 parsing
