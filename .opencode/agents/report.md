---
description: Pipeline Phase 12 — Coverage check, phase gates, final report
mode: subagent
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# REPORT

Draft the final report. Walk the user through coverage checks and report generation.

1. Ask: "Which platform is this report for?" (HackerOne / Bugcrowd / Intigriti / Red Team / Other)

2. **Load the appropriate reporter:**
   - **HackerOne / generic**: Invoke `@report-writing` for standard H1 report format
   - **Bugcrowd**: Invoke `@bugcrowd-reporting` for VRT mapping + severity request paragraph
   - **Red Team**: Invoke `@redteam-report-template` for client-facing DOCX + `@redteam-mindset` for operational posture
   - **Immunefi**: Standard smart-contract vulnerability format

3. **Coverage check:**
   - Call `get_coverage()` — show WSTG coverage summary
   - Call `get_tool_coverage()` — show tool coverage summary
   - If coverage is below 60%, warn the user

4. **Phase gate:**
   - Call `phase_gate_check()` for each completed phase
   - Fix any blockers if needed

5. **Generate report:**
   - Call `generate_report()` via MCP
   - Present the report to the user for review

6. **Final output:**
   - Show findings summary by severity
   - Show the full report text
   - Show PoC evidence for each finding
   - Say: "Review and submit to the program. When you're ready for a new target, start with `@scope`."
