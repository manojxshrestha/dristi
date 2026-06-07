<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/parameter-repetition.md -->
# exec= Parameter Pollution - Repeated Chains & 302 Behavior Change

Technique: mass parameter repetition testing to bypass length filters, trigger parser bugs, or force different code paths / redirects.

**Short repeated exec=bar chain (Content-Length: 98)**
```
POST / HTTP/1.1
Host: redacted.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

exec=bar&exec=bar&exec=bar&exec=bar&exec=bar&exec=bar&exec=bar&exec=bar
```
Response:
```
HTTP/1.0 302 Moved Temporarily
Location: https://redacted.com/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0
```

**Long repeated exec=1 chain (hundreds of repetitions)**
```
exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&...
```
Response:
```
HTTP/1.0 302 Moved Temporarily
Location: http...   (http variant, different scheme!)
Server: BigIP
Connection: Keep-Alive
Content-Length: 0
```

**Key observations:**
- Repeating `exec=bar` (7-8 times) → 302 to **https** with BigIP server  
- Mass repeating `exec=1` (hundreds) → 302 to **http** variant (different scheme)  
- Behavior change (Location URL differing between http/https) suggests the repetition count or parameter flooding is hitting a parser limit, triggering redirect logic, or bypassing normalization/filtering  

This technique (incremental repetition of suspicious params like `exec=`) is commonly used to:
- Overflow internal buffers / argument lists  
- Trigger different redirect logic based on param count  
- Bypass WAF length / repetition rules  
- Leak server-side behavior via 302 Location differences
