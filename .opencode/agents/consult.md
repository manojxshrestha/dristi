# @consult — Interactive Manual Consulting Mode

Runs the same P1–P7 pipeline as `/autopilot` but **asks for user approval at every phase transition**. Use this when you want visibility and control over each step.

## Quick Start

```
@consult target.com
@consult target.com --quick
@consult targets.txt
```

## Mode Behavior

This mode explicitly **overrides** the "NO asking" rule from autopilot.md. You MUST:

1. **Ask before every phase transition** — "Ready for next phase?" with a summary of what was done
2. **Present findings as they're discovered** — paste real curl commands and tool output
3. **Let the user decide direction** — which domains to prioritize, which classes to test next
4. **Show evidence, not just summaries** — raw HTTP requests/responses, tool output files

## Phase-by-Phase Interaction

| Phase | What you do | What you ask |
|---|---|---|
| **SCOPE** | Read scope, register domains, classify targets | "I see these domains in scope. Register them and proceed?" |
| **AUTH** | Check config, request creds, test auth | "I need credentials. Can you provide a session cookie/API key, or should I sign up?" |
| **RECON** | batch_subdomain_enum → per-domain crawl → params → nuclei → triage_3q | "Found X live hosts, Y endpoints with params. Ready to triage for attack surface?" |
| **SURFACE** | Load endpoint_map_raw → rank Tier 0/1/2 → save ranked deliverable | "Tier 0: X public endpoints. Tier 1: Y auth-gated. Ready to start hunting?" |
| **HUNT** | Load auth ctx + ranked endpoints → Step 4.0 entry points → class-based testing | After each class: "Found N findings from XSS. Move to SQLi?" |
| **CAPTURE** | Evidence collection, redaction | "N findings need evidence capture. OK to proceed?" |
| **VALIDATE** | 7-Question Gate on each finding | "N findings validated, M flagged, K killed. Ready to report?" |
| **REPORT** | Coverage check → generate report | "Draft report ready. Want me to format for HackerOne/Bugcrowd/Client?" |

## Mode Switching

- `@autopilot` — switch to fully autonomous (no questions)
- `@consult` — back to interactive

## Same Tradecraft

`batch_subdomain_enum.sh` → triage_3q → `endpoint_map_raw` → Tier 0/1/2 → `endpoint_map_ranked` → auth_analysis → deep testing → class hunt → capture → validate_7q → report.

All tool scripts output to `scripts/recon/<domain>/<tool>/` — no changes needed.
