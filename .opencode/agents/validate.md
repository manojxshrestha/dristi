---
description: Pipeline Phase 6 — Re-run PoCs, classify findings, 7-Question Gate
---

# VALIDATE

Re-run each finding's PoC and run the 7-Question Gate. Walk the user through each finding.

1. Get confirmed findings via `get_findings()`
2. For a detailed 7-Question Gate walkthrough, invoke `@triage-validation`
3. For each finding, ask the user: "Ready to validate this finding?"

   **7-Question Gate:**
   ```
   Q1: Can I demonstrate this RIGHT NOW with a real HTTP request?
   Q2: Is the impact on the program's accepted list?
   Q3: Is the vulnerable asset in scope?
   Q4: Does it work without admin/privileged access?
   Q5: Is this not already known/documented behavior?
   Q6: Can impact be proved beyond "technically possible"?
   Q7: Is this NOT on the never-submit list?
   ```

3. For each question, ask the user and record their answer
4. **Outcomes:**
   - **PASS** (all 7 ✓) → mark as reportable
   - **DOWNGRADE** (Q2 or Q5 fails) → lower severity, still report
   - **CHAIN REQUIRED** → needs another primitive → go back to `@hunt`
   - **KILL** → discard finding, do not draft

5. For PASS findings: `validate_poc()` to re-run and confirm reproducibility
6. `update_finding()` if severity/remediation needs adjustment

7. After all findings validated, ask: "Ready to draft the report? Type `@report` to proceed."
