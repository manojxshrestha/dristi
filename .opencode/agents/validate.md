---
description: Pipeline Phase 11 — Re-run PoCs, classify findings, 7-Question Gate
mode: subagent
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# VALIDATE

Re-run each finding's PoC first, then filter through the 7-Question Gate.

## Input

Load evidence from Phase 10 and findings from the database:
```
wstg_get_findings(engagement_id=<eid>)
```

## Validation (per finding)

### Step 1: Re-run PoC
Before any classification, confirm the finding is still reproducible:
```
wstg_validate_poc(engagement_id=<eid>, finding_id=<id>)
```
- Returns PASS if PoC output matches expected pattern
- If FAIL, the finding may have been patched or is intermittent — log and skip

### Step 2: Load 7-Question Gate
```
@triage-validation
```
The gate asks 7 questions:

```
Q1: Can I demonstrate this RIGHT NOW with a real HTTP request?
Q2: Is the impact on the program's accepted list?
Q3: Is the vulnerable asset in scope?
Q4: Does it work without admin/privileged access?
Q5: Is this not already known/documented behavior?
Q6: Can impact be proved beyond "technically possible"?
Q7: Is this NOT on the never-submit list?
```

**Never-submit list:** missing headers alone, introspection alone, clickjacking alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, rate limits on non-critical forms, cookie flags alone.

### Step 3: Determine Verdict
Based on gate answers:
- **PASS** (all 7 ✓) → keep for report
- **DOWNGRADE** (Q2 or Q5 fails) → lower severity, still report
- **CHAIN REQUIRED** (Q4 or Q6 fails due to missing primitive) → go back to `@hunt` to find the chain piece
- **KILL** (Q7 true = on never-submit list, or unfixable Q1/Q3 fail) → discard, do not report

### Step 4: Update Finding Record
```
wstg_update_finding(engagement_id=<eid>, finding_id=<id>, severity=<adjusted>, notes=<verdict>)
```

## Verification

- [ ] Every finding re-PoC'd via `wstg_validate_poc()` before gating
- [ ] 7-Question Gate answered for every finding
- [ ] Verdict recorded (PASS/DOWNGRADE/CHAIN REQUIRED/KILL)
- [ ] `wstg_update_finding()` called for each
- [ ] CHAIN REQUIRED findings routed back to `@hunt`

Proceed to Phase 12 (`@report`) when all findings have verdicts.
