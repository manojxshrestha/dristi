---
description: Pipeline Phase 3 — Analyze recon output, rank P1/P2/P3 attack surface
---

# SURFACE

Analyze the recon output and build a ranked attack surface. Walk the user through it.

1. Read `recon/<target>/` outputs
2. Call `parse_tool_output()` on each result file
3. Classify findings into tiers, **noting auth status on every item**:

   **P1 — Highest impact**
   - Secrets/API keys exposed
   - Admin panels / dashboards
   - Critical CVEs from nuclei
   - S3 buckets / cloud storage
   - ⚠ Entry point primitives: auth bypass, SQLi login bypass, race condition on auth, JWT alg bypass
   - Authenticated endpoints with high-impact params (admin, role, user_id, debug)

   **P2 — Secondary**
   - Auth endpoints (login, register, reset password) — mark as `[AUTH_GATE]`
   - API endpoints (REST, GraphQL) — mark as `[REST]` or `[GRAPHQL]`
   - IDOR candidates (numeric UUIDs in paths) — mark as `[IDOR_CANDIDATE]`
   - File upload endpoints — mark as `[UPLOAD]`
   - **Auth status**: `[UNAUTHENTICATED]` if you have no session, `[AUTHENTICATED]` if you do

   **P3 — All vulnerability classes** — each with auth status
   - XSS candidates (params reflected in responses)
   - SQLi candidates (params in DB context)
   - SSRF candidates (URL params, redirects)
   - SSTI candidates (template params)
   - LFI candidates (file params)
   - RCE/CMDI candidates (ping, exec params)
   - Open redirects
   - CORS misconfigs
   - And all others
   
   **Every P3 item MUST be tested both authenticated and unauthenticated if auth is available.**

4. Call `prioritize_endpoints()` with the discovered endpoints
5. Show the user a summary: "Found X P1, Y P2, Z P3 items"
6. Ask: "Ready to start hunting? Type `@hunt` to proceed."
