---
description: Interactive Pipeline with Suggestions — Same P1–P12 pipeline as /autopilot, with user approval at every phase transition.
mode: all
permission:
  read: allow
  bash: allow
  write: deny
  edit: deny
  grep: allow
  glob: allow
---

# CONSULT — Interactive Pipeline with AI Analysis

Same P1-P12 pipeline as autopilot, but **you ask the user for approval at every phase** and **suggest what to do next**.

## HARD RULES

1. **Tool execution via pipeline.sh only.** Never run tools or phase scripts directly.
2. **Analysis via task() only.** Dispatch analysis agents for phases 6-12.
3. **NO skipping phases.** Run phases in order.
4. **NEVER install tools.**
5. **Phase 6: You MUST dispatch EVERY agent in the dispatch list.** No exceptions.

## Phase Flow

### Phases 1-5 (bash only — no AI analysis needed)

For each phase N from 1 to 5:
1. **Explain**: "Phase N: <description from pipeline.sh>"
2. **Ask approval**: "Ready?"
3. **Run**: `bash scripts/pipeline.sh <domain> <N>`
4. **Show results**: read output from `$RECON_BASE/<domain>/`, summarize
5. **Suggest next**: explain Phase N+1, ask "Continue?"

### Phase 6: Hunt — Full Agent Dispatch (tools + ALL agents)

Phase 6 has TWO parts: bash tool scanning + AI agent dispatch. BOTH are mandatory.

1. **Explain**: "Phase 6: Vulnerability hunting — param fuzzing, SQLi, XSS scanners + ALL 54 hunting agents"
2. **Ask approval**
3. **Run tools**: `bash scripts/pipeline.sh <domain> 6`
4. **Detect tech stack** from `$RECON_BASE/<domain>/surface/` output
5. **Run dispatch generator**: `bash scripts/dispatch_hunt.sh <domain> --tech <detected_tech>`
6. **Read dispatch list** from `$RECON_BASE/<domain>/hunt/dispatch_list.json`
7. **Show the user** the total agent count and categories to dispatch
8. **Ask approval**: "Dispatch N hunting agents across X categories?"
9. **Dispatch EVERY agent — NO EXCEPTIONS:**
   Loop through `agents[]` in dispatch_list.json and for EACH:
   ```
   task(description="Phase 6: <id> on <domain>", subagent_type="<id>")
   ```
10. **After each agent completes**, update the coverage matrix:
    - Change `pending` → `complete` in the status column
    - Record findings count in the findings column
11. **Show**: findings by severity, bug classes tested, dispatch completion %
12. **Gate check** passes when >= 90% of agents show `complete`
13. **Ask**: "Continue to Phase 7? (Coverage: X/Y agents complete)"

### Phase 7: DeepThink (conditional)

If ALL Phase 6 agents dispatched but **zero confirmed findings**:
1. **Explain**: "Phase 7: Gap analysis — first-principles analysis of why we hit dead ends"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 7`
4. **Read coverage matrix** — identify agents with 0 findings
5. **Analyze**: `task("Gap analysis for <domain> — focusing on agents with 0 findings", subagent_type="deepthink")`
6. **Suggest**: re-run hunt if gaps found, or skip to exploitation

If Phase 6 found findings → skip Phase 7, suggest phase 8 directly.

### Phase 8: Exploit

1. **Explain**: "Phase 8: Exploitation — deepen findings, chain vulns, attempt PoC"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 8`
4. **Analyze**: `task("Exploit findings for <domain>", subagent_type="exploit")`
5. **Update coverage matrix** — add exploitation results to findings column
6. **Show**: exploited vs blocked, chains found
7. **Suggest**: "If WAF bypasses all failed or CVEs missing, run research (search)."
8. **Ask**: "Continue?"

### Phase 9: Search (conditional)

If exploitation stalled:
1. **Explain**: "Phase 9: Research — current CVEs, bypass techniques, disclosed reports"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 9`
4. **Analyze**: `task("Research payloads/CVEs for <domain>", subagent_type="search")`
5. If research found new techniques: suggest re-running phase 8

### Phase 10: Capture

1. **Explain**: "Phase 10: Evidence capture — screenshots, redaction"
2. **Run**: `bash scripts/pipeline.sh <domain> 10`
3. **Analyze**: `task("Capture evidence for <domain>", subagent_type="capture")`
4. **Ask**: "Continue to validation?"

### Phase 11: Validate

1. **Explain**: "Phase 11: Validation — 7-Question Gate on each finding"
2. **Run**: `bash scripts/pipeline.sh <domain> 11`
3. **Analyze**: `task("Validate findings for <domain>", subagent_type="validate")`
4. **Show**: PASS/DOWNGRADE/KILL counts
5. **Ask**: "Generate report?"

### Phase 12: Report

1. **Explain**: "Phase 12: Report — coverage check, final report"
2. **Run**: `bash scripts/pipeline.sh <domain> 12`
3. **Analyze**: `task("Generate report for <domain>", subagent_type="report")`
4. **Ask**: "Which platform? (HackerOne / Bugcrowd / Client)"

## Final Summary

Present findings by severity, domains tested, and report location.
Include from the coverage matrix: total agents dispatched, findings per category, and any skipped agents.
