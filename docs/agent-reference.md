# Agent Reference — When to Use Each

## Methodology & Orchestration

| Agent | When to use |
|-------|-------------|
| `@bb-methodology` | Start of every engagement. 12-phase pipeline: scope → auth → intel → recon → surface → hunt → deepthink → exploit → search → capture → validate → report. Selects mode (bounty/redteam/pentest/audit). |
| `@bug-bounty` | General bug bounty workflow. Program selection, duplicate detection, payout optimization. Use after scope is confirmed. |
| `credential-attack` (skill) | Load via `skill("credential-attack")` when a login endpoint is in scope and program policy permits password testing. 4-stage pipeline: wordlist-gen (cewler → hashcat rules) → breach-check (HIBP k-anonymity) → OSINT employees (theHarvester → username-anarchy) → spray (http-form / oauth / o365 / okta). |
| `@hunt-dispatch` / `@hunt-dispatcher` | When you have a target but don't know which hunt agent to use. Fingerprints tech stack, routes to the correct agent. |
| `@redteam-mindset` | Before any engagement. Sets operational discipline, anti-patterns, burnout avoidance. Read once per engagement. |
| `@web2-vuln-classes` | Reference for 20 bug classes with root causes, bypass tables, exploit techniques. Use when learning a new vuln class or writing reports. |

## Recon & Asset Discovery

| Agent | When to use | Input needed |
|-------|-------------|--------------|
| `@web2-recon` | Start of every web target. Subdomain enum, crawling, endpoint discovery, directory fuzz, JS analysis. | Domain name |
| `@offensive-osint` | Identity mapping, breached credentials, email/phone/social enumeration, org footprint. | Company name, email, username |
| `@osint-methodology` | Source verification, data correlation, persona tracking, geolocation. | Target identity/org |
| `@hunt-source-leak` | When you find `.git`, `.env`, backup files, or debug endpoints. Source map analysis, s3 bucket leaks. | URL or domain |
| `@hunt-subdomain` | When recon finds stale CNAMEs, dangling DNS. Subdomain takeover validation. | CNAME records |

## Exploitation

| Agent | When to use | Input |
|-------|-------------|-------|
| `@exploit` | After Phase 8 EXPLOIT. Loads all findings from the exploitation queue, applies technique guides + payload libraries, attempts PoC exploitation with WAF bypass, and records evidence. | `findings_list_vulns()` |

## Web Application Vulnerabilities

| Agent | When to use | GF input |
|-------|-------------|----------|
| `@hunt-xss` | After `param_extract.sh` → `gf_xss.txt` found candidates. Reflections, stored, DOM, blind XSS. | `gf_xss.txt` |
| `@hunt-sqli` | After `param_extract.sh` → `gf_sqli.txt` found candidates. Classic, blind, second-order. | `gf_sqli.txt` |
| `@hunt-ssrf` | After `param_extract.sh` → `gf_ssrf.txt` found candidates. Params that fetch URLs. | `gf_ssrf.txt` |
| `@hunt-ssrf-cloud` | When SSRF is confirmed and you want to steal cloud metadata (AWS IMDS, GCP, Azure). | SSRF-confirmed endpoint |
| `@hunt-ssti` | After `param_extract.sh` → `gf_ssti.txt`. Jinja2, Twig, Freemarker, Velocity, Jade. | `gf_ssti.txt` |
| `@hunt-lfi` | After `param_extract.sh` → `gf_lfi.txt`. Path traversal, PHP wrappers, log poisoning. | `gf_lfi.txt` |
| `@hunt-rce` | After `param_extract.sh` → `gf_rce.txt`. Command injection, eval(), SSTI→RCE chains. | `gf_rce.txt` |
| `@hunt-nosqli` | After `param_extract.sh` → params hitting MongoDB/CouchDB/Cassandra. `$where`, `$regex` injections. | API endpoint with JSON body |
| `@hunt-ssti` | Template injection in Jinja2, Twig, Freemarker. | `gf_ssti.txt` |
| `@hunt-xxe` | XML endpoints, SOAP APIs, SVG uploads, docx parsing. | Endpoint accepting XML |
| `@hunt-cmdi` | Command injection in params passed to shell/system. | `gf_cmdi.txt` |

## API & Authentication

| Agent | When to use |
|-------|-------------|
| `@hunt-api-misconfig` | API endpoints discovered in recon. Mass assignment, rate limiting gaps, excessive data. |
| `@hunt-graphql` | GraphQL endpoints (`/graphql`, `/graphiql`). Introspection, batching, alias abuse, depth DoS. |
| `@hunt-oauth` | OAuth 2.0 / OIDC flows. Redirect URI bypass, state leakage, CSRF on OAuth, token theft. |
| `@hunt-saml` | SAML SSO endpoints. XML signature wrapping, assertion injection, certificate manipulation. |
| `@hunt-jwt-confusion` | JWT-based auth. Algorithm confusion (RS256→HS256), `none` alg, `kid` injection, JWK spoofing. |
| `@hunt-ato` | Account takeover. Password reset logic flaws, email takeover, 2FA bypass, session hijack. |
| `@hunt-auth-bypass` | Auth endpoints. Forced browsing, method override, parameter pollution, direct endpoint access. |
| `@hunt-session` | Session management. Session fixation, predictable tokens, weak cookie attributes. |

## Business Logic & Specific Flaws

| Agent | When to use |
|-------|-------------|
| `@hunt-business-logic` | Multi-step workflows, pricing manipulation, KYC bypass, coupon abuse. Requires understanding the app flow. |
| `@hunt-race-condition` | Race conditions in payments, coupon redemption, rate limit race, async race. |
| `@hunt-file-upload` | File upload features. SVG XSS, polyglot, zip slip, Content-Type bypass. |
| `@hunt-cache-poison` | CDN-fronted pages. Unkeyed inputs, cache deception, cache key injection. |
| `@hunt-cors` | Cross-origin requests. Origin reflection, wildcard with credentials, preflight bypass. |
| `@hunt-csrf` | State-changing actions without proper tokens. SameSite bypass, JSON CSRF, multi-step. |
| `@hunt-host-header` | Host header injection. Password reset poisoning, cache poisoning, routing-based SSRF. |
| `@hunt-open-redirect` | Redirect params (`redirect=`, `next=`, `url=`). Chaining to phishing/XSS. |
| `@hunt-http-smuggling` | CL.TE, TE.CL, TE.TE variations. WAF bypass, cache poisoning via smuggling. |
| `@hunt-idor` | Object IDs in URLs/params. UUID enum, sequential IDs, GraphQL IDOR, multi-tenant data access. |
| `@hunt-dom` | Client-side vulnerabilities. DOM XSS, clobbering, prototype pollution, trusted types bypass. |
| `@hunt-brute-force` | Login endpoints, OTP/2FA brute force, JWT brute force, rate limiting bypass. |
| `@hunt-mfa-bypass` | MFA implementations. Push fatigue, backup code reuse, biometric bypass, SIM swap. |
| `@hunt-deserialization` | PHP unserialize, Java deserialization (ysoserial), .NET ViewState, pickle, Ruby MARSHAL. |
| `@hunt-websocket` | WebSocket connections. Message injection, origin bypass, CSWSH, WS proxy misconfig. |
| `@hunt-tls-network` | TLS/SSL weaknesses. Weak ciphers, outdated TLS, cert validation bypass, STARTTLS. |

## Framework-Specific

| Agent | When to use |
|-------|-------------|
| `@hunt-laravel` | Laravel apps. Debug mode, APP_KEY decryption, mass assignment, Blade SSTI, Eloquent injection. |
| `@hunt-springboot` | Spring Boot apps. Actuator exposure, SpEL injection, property injection, classpath RCE. |
| `@hunt-aspnet` | ASP.NET / .NET apps. ViewState deserialization, machineKey disclosure, IIS misconfig. |
| `@hunt-nextjs` | Next.js apps. Vercel misconfig, SSG/SSR leaks, middleware bypass, RSC injection. |
| `@hunt-nodejs` | Node.js/Express apps. Prototype pollution, unsafe eval, dependency vulns. |
| `@hunt-sharepoint` | SharePoint on-prem/online. Privilege escalation, workflow abuse, ViewState deserialization. |

## Infrastructure & Cloud

| Agent | When to use |
|-------|-------------|
| `@cloud-iam-deep` | Cloud IAM review. AWS (24+ priv-esc patterns), Azure RBAC, GCP IAM misconfig |
| `@hunt-cloud-misconfig` | Open S3/Azure Blob/GCP buckets, public AMIs, unsecured databases, cloud metadata. |
| `@hunt-k8s` | Kubernetes clusters. RBAC abuse, pod escape, secrets exposure, kubelet API. |
| `@hunt-cicd` | CI/CD pipelines. GitHub Actions injection, GitLab CI abuse, Jenkins pipeline groovy. |
| `@enterprise-vpn-attack` | VPN appliances. Cisco ASA/FTD, Fortinet, Citrix, Palo Alto, Pulse Secure CVEs. |
| `@m365-entra-attack` | Microsoft 365 / Entra ID. Conditional Access bypass, token theft, device registration abuse. |
| `@okta-attack` | Okta as IdP. SWA injection, delegated auth flaws, API token abuse. |

## Mobile & Specialized

| Agent | When to use |
|-------|-------------|
| `@apk-redteam-pipeline` | Android APK testing. Decompile (jadx/apktool), secret grep, Frida, cert pinning bypass. |
| `@meme-coin-audit` | Token/smart contract audit. Rug-pull detection, honeypot analysis, liquidity lock. |
| `@hunt-llm-ai` | LLM/AI apps. Prompt injection, RAG poisoning, model extraction, jailbreak. |
| `@hunt-ldap` | LDAP directories. Injection, anonymous binds, AD/LDAP misconfig. |
| `@hunt-ntlm-info` | NTLM auth. Challenge capture, relay primitives, coercion, NetNTLMv2 intercept. |

## Reporting & Post-Engagement

| Agent | When to use |
|-------|-------------|
| `@report-writing` | Writing findings. HackerOne/Bugcrowd/Intigriti/Immunefi templates, CVSS scoring, impact. |
| `@bugcrowd-reporting` | Bugcrowd-specific reports. VRT mapping, OOS rebuttal, alias hygiene. |
| `@evidence-hygiene` | Before submitting evidence. Cookie/PII redaction, HAR sanitization, screenshot metadata strip. |
| `@triage-validation` | Before submitting. 7-Question Gate: real request? accepted impact? in-scope? verdict: PASS/KILL. |
| `@redteam-report-template` | Client-facing deliverables. DOCX templates with PoC screenshots, executive summary. |
| `@hunt-misc` | Catch-all. When no other agent fits. Emerging threats, zero-day patterns, uncommon surfaces. |
| `@supply-chain-attack-recon` | Dependency confusion, package squatting, typosquatting, SBOM mining. |

## Quick Command Reference

| Command | What it does |
|---------|-------------|
| `/recon` | Run recon pipeline (subdomain enum → crawl → params → cariddi) |
| `/hunt` | Run hunt pipeline (XSS → SQLi → secrets) |
| `/surface` | Map attack surface from recon data |
| `/intel` | Gather threat intelligence on target |
| `/pickup` | Resume interrupted engagement |
| `/report` | Generate findings report |
| `/triage` | Triage and validate findings |
| `/validate` | Re-validate PoC for a finding |
| `/token-scan` | Scan for hardcoded tokens |
| `/memory-gc` | Memory garbage collection |
| `/remember` | Save context for next session |
| `/chain` | Find attack chains between findings |
| `/autopilot` | Full auto: recon → hunt → report |

## Automation Scripts → Agent Mapping

| Script output | Feeds into |
|---------------|------------|
| `params/gf_xss.txt` | `@hunt-xss` |
| `params/gf_sqli.txt` | `@hunt-sqli` |
| `params/gf_ssrf.txt` | `@hunt-ssrf` + `@hunt-ssrf-cloud` |
| `params/gf_ssti.txt` | `@hunt-ssti` |
| `params/gf_lfi.txt` | `@hunt-lfi` |
| `params/gf_rce.txt` | `@hunt-rce` |
| `params/gf_redirect.txt` | `@hunt-open-redirect` |
| `params/gf_idor.txt` | `@hunt-idor` |
| `params/gf_cmdi.txt` | `@hunt-rce` |
| `params/gf_xxe.txt` | `@hunt-xxe` |
| `params/gf_lfi.txt` | `@hunt-lfi` |
| `cariddi/cariddi.txt` | `@hunt-source-leak` |
| `secrets/` findings | All relevant hunt agents |
| `crawl/crawledurls.txt` | `@hunt-api-misconfig`, `@hunt-graphql` |
