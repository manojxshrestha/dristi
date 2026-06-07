<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/burp-workflow.md -->
# Burp Suite Workflow

## Quick Reference - Request/Response Patterns

### 1. Minimal Request (Low Noise)
```
GET / HTTP/1.1
Host: target.com
```

### 2. Amplified Request (High Signal)
```
GET / HTTP/1.1
Host: target.com
X-U: a
X-U: a
X-U: a
... (255 times)
```

### 3. Discovery Overload Request
```
GET /?foo=random HTTP/1.1
Host: target.com
```

### 4. Parameter Pollution Request
```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 98

exec=bar&exec=bar&exec=bar&exec=bar&exec=bar&exec=bar&exec=bar&exec=bar
```

### 5. Encoded Injection Request
```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

exec=(()+{3a3b+}%3b+echo+1
```

### 6. SQLi Timing Request
```
GET /api/alert?mic=' HTTP/1.1
Host: target.com
```

## Common Response Patterns

### Normal Response
```
HTTP/1.1 200 OK
Content-Length: 50
```

### Cache Hit (Fast)
```
HTTP/1.1 200 OK
Content-Length: 22
Response-Time: 22ms
```

### Cache Miss (Slow)
```
HTTP/1.1 200 OK
Content-Length: 310
Response-Time: 310ms
```

### Connection Closed
```
HTTP/1.1 200 OK
Connection: close
```

### BigIP Redirect
```
HTTP/1.0 302 Moved Temporarily
Location: https://target.com/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0
```

## Testing Workflow
1. **Baseline**: Send minimal request, note response time
2. **Amplify**: Add repeated headers, measure delta
3. **Probe**: Test various parameters, look for timing differences
4. **Identify**: Find interesting parameters (slow responses, connection closes)
5. **Exploit**: Use encoding/pagination to bypass WAF
6. **Scale**: Increase repetition, observe behavior changes

## Tips
- Use the **Add** button to add headers in Repeater
- Use the **Remove** button to strip noisy headers
- Drag the send slider to 10-12 seconds for slow send testing
- Monitor response times in the timeline
- Look for 302 redirects with different Location schemes
