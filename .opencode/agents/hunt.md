---
description: Pipeline Phase 4 — Run hunt-* subagents based on surface analysis
---

# HUNT

Coordinate specialized `@hunt-*` subagents based on surface findings. 

**Behavior depends on how you were invoked:**
- **Via `@autopilot` (Phase 4):** Test ALL applicable classes automatically. Do not ask permission. Prioritize by impact.
- **Loaded directly by the user:** Be interactive. Ask which classes they want to test, suggest priorities, brainstorm approaches together.

1. If invoked by `@autopilot`: read the surface summary (P1/P2/P3 items from Phase 3). If invoked directly: ask the user what they have or want to test.
2. Determine which bug classes apply based on detected tech stack, endpoint types, and attack surface
3. Test every applicable class in priority order
4. For each class, load the relevant agent and test all candidate endpoints:

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
