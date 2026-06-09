---
description: Pipeline Phase 4 — Run hunt-* subagents based on surface analysis
---

# HUNT

Coordinate specialized `@hunt-*` subagents based on surface findings. 

**Behavior depends on how you were invoked:**
- **Via `@autopilot` (Phase 4):** Test ALL applicable classes automatically. Do not ask permission. Prioritize by impact.
- **Loaded directly by the user:** Be interactive. Ask which classes they want to test, suggest priorities, brainstorm approaches together.

## Critical Mindset: Entry Point First

**Stop looking at what the server sends you. Start looking at what the server accepts from you.**

Before running any class-specific tests (XSS, SQLi, etc.), you MUST first find the **entry point** — the primitive that opens the door for everything else. Working without an entry point means every test is blind.

Ask yourself:
- **Do I have auth?** If yes, what can I do now that I couldn't before? If no, getting auth is priority #1.
- **Does the API accept unexpected input?** Try JSON→XML→form→multipart on the same endpoint. Try HTTP method override headers. Try parameter pollution.
- **Are there race conditions?** Test auth flows: signup, login, password reset, OTP validation.
- **Is there GraphQL?** Test introspection, batching, alias-based enumeration.
- **Are there JWTs?** Decode them, test alg confusion, kid injection, jwk header injection.
- **Are there UUIDs?** Analyze patterns, try enumeration, path traversal, type confusion.
- **Is there a mobile API?** Different User-Agent, different endpoints, weaker auth.

**The #1 mistake: jumping to class-based hunting (XSS, SQLi, etc.) without finding an entry point first. Every post-exploitation finding requires a precondition you don't have until you find the foothold.**

## Entry Point Testing (Run This First)

Before any class-based hunting, run these techniques. They find the precondition that everything else depends on:

### 1. Auth Status Check
```bash
curl -sv https://<target>/api/me -H "Authorization: Bearer <token>" 2>&1
curl -sv https://<target>/api/user/profile -b "session=<cookie>" 2>&1
```
- Label all findings as `[AUTHENTICATED]` or `[UNAUTHENTICATED]`

### 2. API Fuzzing (Hidden Params)
- Run `arjun` on every API endpoint
- Run `x8` with a parameter wordlist
- Look for: `admin`, `role`, `is_admin`, `is_public`, `user_id`, `debug`, `bypass`, `override`, `test`

### 3. HTTP Method Override
- Try `X-HTTP-Method-Override: PUT/PATCH/DELETE` on every endpoint
- Try `X-Method-Override`, `X-HTTP-Method`
- A GET-only endpoint might accept POST when overridden

### 4. Content-Type Switching
- Send JSON endpoints as XML → may expose XXE
- Send JSON as form-encoded → may bypass validation
- Send as multipart → may bypass content-type checks

### 5. GraphQL Probing (if detected)
- Introspection query
- Batching attack (rate limit bypass via array)
- Alias-based resource enumeration

### 6. Auth Flow Race Conditions
- Race signup (same email 20x)
- Race password reset
- Race OTP/2FA validation

### 7. UUID Analysis
- Check for sequential/timestamp patterns
- Try null UUID, all-zeros, all-ffs
- Path traversal in UUID param

### 8. JWT Manipulation (if found)
- Decode with `jwt_tool`
- Test `alg: none` bypass
- Test `kid` injection (path traversal)
- Test JWK header injection

### 9. Mobile API Surface
- Different User-Agent: `curl -H "User-Agent: Mobile/1.0"`
- Different API version: try `/v1/`, `/v2/`, `/mobile/`

## If Entry Point Found
- Log it as a finding
- Re-run entry point techniques with the new access level
- Then proceed to class-based hunting with auth context

## If No Entry Point Found
- Proceed with `[UNAUTHENTICATED]` label on all findings
- Focus on auth-free bugs: source leaks, open buckets, CORS, subdomain takeover
- Accept that the target is hardened — adjust expectations

## Class-Based Hunting

1. Determine which bug classes apply based on detected tech stack, endpoint types, and attack surface
2. Test every applicable class in priority order
3. For each class, load the relevant agent and test all candidate endpoints:

| Class | Agent to invoke |
|-------|-----------------|
| XSS | `@hunt-xss` |
| SQLi | `@hunt-sqli` |
| SSRF | `@hunt-ssrf` |
| IDOR | `@hunt-idor` |
| SSTI | `@hunt-ssti` |
| LFI | `@hunt-lfi` |
| RCE/CMDI | `@hunt-rce` |
| Auth bypass | `@hunt-auth-bypass` |
| ATO | `@hunt-ato` |
| API misconfig | `@hunt-api-misconfig` |
| GraphQL | `@hunt-graphql` |
| File upload | `@hunt-file-upload` |
| Race condition | `@hunt-race-condition` |
| OAuth | `@hunt-oauth` |
| CORS | `@hunt-cors` |
| XXE | `@hunt-xxe` |
| CSRF | `@hunt-csrf` |
| Host header | `@hunt-host-header` |
| Cache poison | `@hunt-cache-poison` |
| Deserialization | `@hunt-deserialization` |
| WebSocket | `@hunt-websocket` |
| Subdomain takeover | `@hunt-subdomain` |
| NTLM info | `@hunt-ntlm-info` |
| Cloud misconfig | `@hunt-cloud-misconfig` |
| Business logic | `@hunt-business-logic` |
| Brute force | `@hunt-brute-force` |
| CI/CD | `@hunt-cicd` |
| Open redirect | `@hunt-open-redirect` |
| LLM/AI | `@hunt-llm-ai` |
| Prototype pollution | `@hunt-nodejs` / `@hunt-dom` |
| NoSQLi | `@hunt-nosqli` |
| LDAPi | `@hunt-ldap` |
| JWT confusion | `@hunt-jwt-confusion` |
| HTTP smuggling | `@hunt-http-smuggling` |
| ATO | `@hunt-ato` |
| ASP.NET | `@hunt-aspnet` |
| Laravel | `@hunt-laravel` |
| Spring Boot | `@hunt-springboot` |
| Next.js | `@hunt-nextjs` |
| Node.js | `@hunt-nodejs` |
| SAML | `@hunt-saml` |
| Session mgmt | `@hunt-session` |
| SharePoint | `@hunt-sharepoint` |
| Source leak | `@hunt-source-leak` |
| MFA bypass | `@hunt-mfa-bypass` |
| TLS/SSL | `@hunt-tls-network` |
| Misc | `@hunt-misc` |
| M365/Entra | `@m365-entra-attack` |
| Cloud IAM | `@cloud-iam-deep` |
| Enterprise VPN | `@enterprise-vpn-attack` |
| Okta | `@okta-attack` |
| Meme coin audit | `@meme-coin-audit` |
| Supply chain | `@supply-chain-attack-recon` |
| K8s | `@hunt-k8s` |
| Android APK | `@apk-redteam-pipeline` |
| OSINT | `@offensive-osint` |

4. For each confirmed finding:
   - `validate_poc()` via MCP to verify
   - `log_finding()` with evidence
   - `track_test()` for WSTG coverage
   - `create_exploitation_queue()` if chainable

5. For chaining opportunities between findings, call `@hunt-dispatch` to identify attack chains
6. When done: if via `@autopilot`, proceed to `@capture` automatically. If loaded directly, tell the user what was found and ask how they want to proceed.
