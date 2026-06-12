---
description: Pipeline Phase 2 — Authenticate to target, capture tokens, cookies, and session state
mode: all
permission:
  read: allow
---

# AUTH — Phase 2

Authenticate to the target application and persist session state for subsequent testing.

## What This Does

1. Accepts credentials (username/password, token, API key)
2. Completes the auth flow (login, OAuth, SSO, MFA)
3. Captures session tokens, cookies, and auth headers
4. Saves auth deliverable for downstream agents
