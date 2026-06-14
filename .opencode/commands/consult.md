---
name: consult
description: Interactive P1–P12 pipeline with human go-ahead at each phase. Suggests next steps and alternatives. Usage: /consult target.com [--quick|--deep]
---

# /consult

Interactive hunt mode. Same P1–P12 pipeline as `/autopilot` but with human approval at every phase transition. The assistant suggests what to do next and offers alternatives.

## Usage

```
/consult target.com                    # full interactive pipeline
/consult target.com --quick            # faster, fewer deep tests
/consult target.com --deep             # exhaustive testing
/consult targets.txt                   # multi-target from file
```

## Phase Flow

After each phase completes, the assistant:
1. Shows a summary of what was found
2. **Suggests** the recommended next step with reasoning
3. Offers alternatives
4. Asks "Ready?"

```
Phase 1 (SCOPE)       → suggest next → ask user → advance on approval
Phase 2 (AUTH)        → suggest next → ask user → advance on approval
Phase 3 (INTEL)       → suggest next → ask user → advance on approval
Phase 4 (RECON)       → suggest next → ask user → advance on approval
Phase 5 (SURFACE)     → suggest next → ask user → advance on approval
Phase 6 (HUNT)        → suggest next → ask user → advance on approval
Phase 7 (DEEPTHINK)  → suggest next → ask user → advance on approval (conditional)
Phase 8 (EXPLOIT)     → suggest next → ask user → advance on approval
Phase 9 (SEARCH)      → suggest next → ask user → advance on approval (conditional)
Phase 10 (CAPTURE)    → suggest next → ask user → advance on approval
Phase 11 (VALIDATE)   → suggest next → ask user → advance on approval
Phase 12 (REPORT)     → suggest next → ask user → advance on approval
```

## What The Assistant Suggests

| Phase | Summary shown | Suggested next | Alternatives |
|---|---|---|---|---|
| SCOPE | Domains registered, scope confirmed | "Get credentials for authenticated testing" | "Skip auth, go unauthenticated" |
| AUTH | Auth method documented, token saved | "Run passive intel (OSINT)" | "Skip intel, go straight to recon" |
| INTEL | WHOIS, cloud buckets, spoof check | "Run full recon — 17 tools" | "Quick recon (--quick) or skip to surface" |
| RECON | Live hosts, endpoints, secrets found | "Rank attack surface into tiers" | "Start hunting Tier 0 immediately" |
| SURFACE | Tier 0/1/2 list built | "Start hunting — recommend class order by impact" | "Focus on specific class, or run all" |
| HUNT | Findings by severity | "Run gap analysis (deepthink) if zero findings" | "Skip to exploitation" |
| DEEPTHINK | (conditional) Gaps documented, root causes identified | "Re-dispatch HUNT with gap fixes" | "Skip to exploitation anyway" |
| EXPLOIT | Findings exploited or blocked | "Run research (search) if blocked by WAF/CVEs" | "Proceed to capture" |
| SEARCH | (conditional) CVEs/payloads researched | "Re-dispatch EXPLOIT with fresh payloads" | "Proceed to capture" |
| CAPTURE | Evidence saved, redacted | "Validate through 7-Question Gate" | "Skip validation, go straight to report" |
| VALIDATE | PASS/DOWNGRADE/KILL counts | "Draft final report" | "Review findings before reporting" |

## Safety

- Every URL checked against scope allowlist
- Every request logged to engagement audit
- Reports NEVER auto-submitted
- PUT/DELETE/PATCH require explicit approval
