---
name: waf-protocol-evasion
description: Skill for bypassing WAFs using HTTP protocol-level manipulation including SSL/TLS cipher selection, HTTP/0.9 downgrade, request smuggling, and chunked encoding abuse. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 10
---

# WAF Protocol Evasion

## Crown Jewel Targets

- WAFs with SSL termination (cipher-based bypass)
- Reverse proxies with HTTP parsing differences
- WAFs that don't handle non-standard HTTP versions
- Load balancers with different protocol handling than WAF

## Attack Surface Signals

- WAF behaves differently with different TLS ciphers
- HTTP/0.9 requests bypass WAF rules
- Chunked encoding requests are not inspected
- Transfer-Encoding manipulation reveals proxy differences

## Step-by-Step Methodology

1. **SSL/TLS Cipher Abuse**: Test different cipher suites to find uninspected ones
   ```bash
   curl --ciphers 'ECDHE-RSA-AES128-GCM-SHA256' -k https://target.com/?q=<script>
   ```
2. **HTTP/0.9 Downgrade**: Send minimal requests without headers
   ```
   GET /\x0d\x0a
   ```
3. **Request Smuggling**: Exploit Content-Length vs Transfer-Encoding discrepancies
   ```http
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 5
   Transfer-Encoding: chunked

   0

   GET /admin HTTP/1.1
   Host: target.com
   ```
4. **Chunked Encoding Abuse**: Hide payloads in chunked transfer encoding
5. **HTTP Method Manipulation**: Use non-standard or lowercase methods

## Technique Reference

| Technique | Description | Tool |
|-----------|-------------|------|
| SSL/TLS Cipher Abuse | Use specific ciphers to bypass inspection | abuse-ssl-bypass-waf |
| HTTP/0.9 | Request without headers | Netcat/raw sockets |
| Request Smuggling | CL.TE, TE.CL discrepancies | smuggler.py |
| Chunked Encoding | Hide payloads in chunked body | curl with custom encoding |
| Method Manipulation | Case variation, non-standard methods | curl -X |

## Request Smuggling Payload

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X
```

## Common Root Causes

- WAFs and backends parse HTTP protocol differently
- SSL/TLS inspection is cipher-selective on some WAFs
- HTTP/0.9 lacks headers, making rule application difficult
- Chunked encoding may not be decoded by the WAF
- HTTP method variations bypass case-sensitive rules

## Gate 0 Validation

- [ ] Have I tested SSL/TLS cipher variation?
- [ ] Have I tested HTTP protocol downgrade?
- [ ] Have I tested request smuggling?
- [ ] Have I tested non-standard HTTP methods?
