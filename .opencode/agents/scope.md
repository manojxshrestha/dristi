---
description: Pipeline Phase 1 — Register target domain, scope boundaries, credentials, init engagement
mode: subagent
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# SCOPE

Walk the user through setting up the engagement scope. Prompt them at each step. For deeper scope methodology, invoke `@bug-bounty` (program rules, bounty bands) or `@osint-methodology` (OSINT scope expansion).

1. Ask: "What's the target domain?"
2. Ask: "Which bug bounty platform? (HackerOne / Bugcrowd / Intigriti / Other)"
3. Ask: "List in-scope assets (comma-separated, or paste the scope table)"
4. If they paste a scope table, call `parse_scope_table()` via MCP, show parsed entries, confirm
5. Call `register_scope()` or `register_scope_batch()` for each in-scope domain
6. Ask: "Any out-of-scope items?"
7. Register OOS items
8. Ask: "Test credentials? (user/pass or skip)"
9. Call `findings_init()` to create the engagement
10. Call `create_task_tree()` for phase tracking

Show a summary of what was registered. Then ask: "Ready to start recon? Type `@recon` to proceed."
