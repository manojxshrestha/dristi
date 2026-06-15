---
name: autopilot
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
/autopilot target.com --quick            # fast surface scan, fewer checks, lower token use
/autopilot targets.txt                   # multiple targets — one domain per line in the file
```

## Session Isolation (Important)

**Start a fresh OpenCode session per target.** OpenCode accumulates context across a session —
testing multiple targets in one session causes cross-contamination where findings, payloads,
and tech stack assumptions from target A bleed into target B.

Best practice:
```bash
# Terminal 1: target A
opencode  →  /autopilot targetA.com

# Terminal 2: target B (separate process)
opencode  →  /autopilot targetB.com
```

If you must test multiple targets in one session, run `/pickup target.com` at the start of
each target switch to reload the correct context.

## Token Optimization

Use `--quick` for faster, lower-cost scans (skips deep fuzzing and extended nuclei templates):
```
/autopilot target.com --quick    # ~40% fewer tokens, covers main attack surface
/hunt target.com --vuln-class idor   # single bug class — lowest token use
```

For long hunts, run `/compact` (OpenCode built-in) periodically to compress context
without losing findings.

## What This Does

Runs the full 12-phase autonomous pipeline without stopping for approval at each step:

```
Phase 1:  SCOPE      → Register domains, load config, create task tree
Phase 2:  AUTH       → Test credentials, detect WAF, save auth deliverable
Phase 3:  INTEL      → Passive OSINT: WHOIS, M365, cloud, spoof check
Phase 4:  RECON      → Subdomain enum, crawl, cariddi, nuclei, 403 bypass, vhost, zone transfer, cloud recon, CVE scan, secrets
Phase 5:  SURFACE    → Load recon, classify tiers + functional groups, prioritize endpoints
Phase 6:  HUNT       → Test all bug classes via 54 hunt-* sub-agents (group-based + Ralph Wiggum loop + parallel credential-attack)
Phase 7:  DEEPTHINK  → (conditional) Gap analysis when HUNT yields zero
Phase 8:  EXPLOIT    → Deepen findings, multi-auth-context probing, exhaustive exploitation gate
Phase 9:  SEARCH     → (conditional) 13-resource retrieval when EXPLOIT stalls
Phase 10: CAPTURE    → Evidence collection, screenshots, redaction
Phase 11: VALIDATE   → Re-validate PoCs, 7-Question Gate
Phase 12: REPORT     → Coverage check, generate final report
```

## Safety Guarantees

- **Every URL** is checked against the scope allowlist before any request
- **Every request** is logged to `hunt-memory/audit.jsonl`
- **Reports are NEVER auto-submitted** — always requires explicit approval
- **PUT/DELETE/PATCH** require human approval in --yolo mode (safe methods only)
- **Circuit breaker** stops hammering if 5 consecutive 403/429/timeout on same host
- **Rate limited** at 1 req/sec (testing) and 10 req/sec (recon)

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/pickup target.com` next time to pick up where you left off
- Check `hunt-memory/audit.jsonl` for a full request log
