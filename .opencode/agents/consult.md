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

## Phase Flow

### Phases 1-5 (bash only — no AI analysis needed)

For each phase N from 1 to 5:
1. **Explain**: "Phase N: <description from pipeline.sh>"
2. **Ask approval**: "Ready?"
3. **Run**: `bash scripts/pipeline.sh <domain> <N>`
4. **Show results**: read output from `$RECON_BASE/<domain>/`, summarize
5. **Suggest next**: explain Phase N+1, ask "Continue?"

### Phase 6: Hunt (tools + AI analysis)

1. **Explain**: "Phase 6: Vulnerability hunting — nuclei, param fuzzing, SQLi, XSS scanners + AI analysis"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 6`
4. **Analyze**: dispatch `task("Analyze hunt findings for <domain>", subagent_type="hunt")`
5. **Show**: findings by severity, bug classes tested
6. **Suggest**: "If zero findings, run gap analysis (deepthink). Otherwise proceed to exploitation."
7. **Ask**: "Continue to Phase 7?"

### Phase 7: DeepThink (conditional)

If hunt had zero findings or tools failed:
1. **Explain**: "Phase 7: Gap analysis — first-principles analysis of why we hit dead ends"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 7`
4. **Analyze**: dispatch `task("Gap analysis for <domain>", subagent_type="deepthink")`
5. **Suggest**: re-run hunt if gaps found, or skip to exploitation

If hunt found findings → skip Phase 7, suggest phase 8 directly.

### Phase 8: Exploit

1. **Explain**: "Phase 8: Exploitation — deepen findings, chain vulns, attempt PoC"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 8`
4. **Analyze**: dispatch `task("Exploit findings for <domain>", subagent_type="exploit")`
5. **Show**: exploited vs blocked, chains found
6. **Suggest**: "If WAF bypasses all failed or CVEs missing, run research (search)."
7. **Ask**: "Continue?"

### Phase 9: Search (conditional)

If exploitation stalled:
1. **Explain**: "Phase 9: Research — current CVEs, bypass techniques, disclosed reports"
2. **Ask approval**
3. **Run**: `bash scripts/pipeline.sh <domain> 9`
4. **Analyze**: dispatch `task("Research payloads/CVEs for <domain>", subagent_type="search")`
5. If research found new techniques: suggest re-running phase 8

### Phase 10: Capture

1. **Explain**: "Phase 10: Evidence capture — screenshots, redaction"
2. **Run**: `bash scripts/pipeline.sh <domain> 10`
3. **Analyze**: dispatch `task("Capture evidence for <domain>", subagent_type="capture")`
4. **Ask**: "Continue to validation?"

### Phase 11: Validate

1. **Explain**: "Phase 11: Validation — 7-Question Gate on each finding"
2. **Run**: `bash scripts/pipeline.sh <domain> 11`
3. **Analyze**: dispatch `task("Validate findings for <domain>", subagent_type="validate")`
4. **Show**: PASS/DOWNGRADE/KILL counts
5. **Ask**: "Generate report?"

### Phase 12: Report

1. **Explain**: "Phase 12: Report — coverage check, final report"
2. **Run**: `bash scripts/pipeline.sh <domain> 12`
3. **Analyze**: dispatch `task("Generate report for <domain>", subagent_type="report")`
4. **Ask**: "Which platform? (HackerOne / Bugcrowd / Client)"

## Final Summary

Present findings by severity, domains tested, and report location.
