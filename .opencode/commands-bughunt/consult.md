---
name: consult
description: Manual consulting mode — interactive P1–P7 hunt with human go-ahead at each phase. Usage: /consult target.com [--quick|--deep]
---

# /consult

Interactive hunt mode. Same P1–P7 pipeline as `/autopilot` but with a human go-ahead at every phase transition. You drive the work, the user drives the direction.

## Usage

```
/consult target.com                    # full interactive pipeline
/consult target.com --quick            # faster, fewer deep tests
/consult targets.txt                   # multi-target from file
/consult --phase 1 target.com          # jump to phase 1 (scope)
```

## Phase Flow (Tab to advance)

After each phase completes, the assistant asks "Ready for next phase?" Type `y` or press Enter to advance, `s` to skip, `q` to stop.

```
Phase 1 (SCOPE)       →  ask user → [y/s/q]
Phase 1.5 (AUTH)      →  ask user → [y/s/q]
Phase 2 (RECON)       →  ask user → [y/s/q]
Phase 3 (SURFACE)     →  ask user → [y/s/q]
Phase 4 (HUNT)        →  ask user → [y/s/q]
Phase 5 (CAPTURE)     →  ask user → [y/s/q]
Phase 6 (VALIDATE)    →  ask user → [y/s/q]
Phase 7 (REPORT)      →  ask user → [y/s/q]
```

## What the Assistant Does Per Phase

| Phase | Assistant does | Asks user |
|---|---|---|
| SCOPE | Reads scope, registers domains, creates task tree | "Domains registered. Ready for Phase 1.5 (auth)?" |
| AUTH | Checks for credentials, tests auth flow | "Need creds or continue [UNAUTHENTICATED]?" |
| RECON | Runs batch subdomain enum + per-domain sequential | "34 live hosts found. Crawl them?" |
| SURFACE | Loads endpoint_map_raw, builds Tier 0/1/2 | "12 public+input endpoints identified. Start hunting?" |
| HUNT | Tests Tier 0 → Tier 1 → Tier 2 per class | "XSS found <N>. Next class?" |
| CAPTURE | Takes screenshots, redacts PII | "Evidence captured. Validate?" |
| VALIDATE | Runs 7-Question Gate on each finding | "3 findings PASSED. Draft report?" |
| REPORT | Generates report per platform template | "Report ready at <path>. Submit?" |

## What This Does Behind the Scenes

Same tools, same tradecraft, same mindset as `/autopilot`:

```
batch_subdomain_enum.sh → dns_bruteforce → web_crawl → param_extract
  → cariddi → nuclei → dir_bruteforce → triage_3q → endpoint_map_raw
  → surface Tier 0/1/2 → endpoint_map_ranked → deep_testing → class hunt
  → capture → validate_7q → generate_report
```

## Mode Switching

- Type `/autopilot` to switch to fully autonomous mode (no more questions)
- Type `/consult` to switch back to interactive mode
- Type `/next` to advance to the next phase without waiting for the prompt
