# `bughunt` — claude-bughunter CLI

> **Secondary interface — slash commands are primary.** Inside a Claude Code conversation, use the slash commands (`/recon`, `/hunt`, `/triage`, `/report`, `/validate`, `/chain`, `/autopilot`, `/scope`, etc.) — they leverage the full skill content and the LLM's judgment.

`bughunt` is the **terminal-native deterministic runner** — use it when you're outside Claude Code, automating in CI/CD, running scheduled recon, or verifying labs reproducibly. Same skills, different execution model.

## When to use `bughunt` vs slash commands

| Use case | Use this |
|---|---|
| Hunting a new target conversationally, applying judgment | **Slash commands** in Claude Code (`/hunt`, `/triage`, etc.) |
| Building a chain across multiple primitives | **Slash commands** — LLM keeps state across the conversation |
| Scheduled / CI / scripted runs | **`bughunt`** — deterministic exit codes, identical output across runs |
| Bulk passive recon (hundreds of subdomains) | **`cbh recon`** — real `subfinder`/`dig`/`curl`, no LLM in the loop |
| Verifying labs / reproducing claims | **`bughunt`** — every Phase 2 doc's curls work via `bughunt` too |
| Reading skills without Claude Code installed | **`bughunt`** + browsing `skills/` and `docs/disclosed-reports/` |
| Triage gate at PR time / pre-submit linting | **`cbh triage`** — deterministic keyword-match against the 7-Question Gate |

The two interfaces consume the same content (`skills/` + `docs/disclosed-reports/`). They produce different outputs because they execute differently. Pick by context, not by preference.

## Operating modes for the CLI

> Stdlib + optional `subfinder` for richer recon. No build step.

**Two HTTP-routing modes** within the CLI — pick what fits your setup:
1. **Curl-only (default)** — stdlib HTTP, no Burp dependency. Works on any laptop with Python 3.9+.
2. **Burp Suite integration** — `--burp` flag routes everything through Burp's proxy (default `127.0.0.1:8080`). Requests + responses land in Project / Target / Scope — makes manual follow-up seamless.

## Available commands

### `bughunt recon [target]`

Full reconnaissance pipeline: subdomain enumeration → live host probing → port scanning → technology fingerprinting → endpoint crawling.

- Output: `$DRISTI_ROOT/engagements/recon/<target>/`
- Supports `--passive` (no direct touch), `--active` (full probe), `--quick` (top 20 subdomains only)

### `bughunt hunt [target] [--class <vuln-class>]`

Run targeted vulnerability hunting against a target. If `--class` is omitted, runs the full hunt suite.

- Output: `~/.bughunt/output/<target>/hunt/`
- Applies the same methodology as the `@hunt-*` agents but in deterministic mode
- Supports `--param <key=value>` for custom parameter injection

### `bughunt triage [finding-dir]`

Apply the 7-Question Gate to each finding: real request? accepted impact? in-scope? not admin-only? concrete? not on never-submit? verdict.

- Exits non-zero if any finding fails triage
- Output: triage report with PASS/KILL/DOWNGRADE/CHAIN-REQUIRED per finding

### `bughunt report [target]`

Generate a markdown penetration test report from findings database. Same output as `generate_report()` but from the CLI.

### `bughunt validate [finding-id]`

Re-validate a logged finding by re-running its PoC. Wraps `validate_finding_poc()`.

### `bughunt chain [finding-ids...]`

Check for chaining opportunities between findings. Wraps `find_chains()`.

### `bughunt autopilot [target]`

Run the full 12-phase pipeline autonomously: SCOPE → AUTH → INTEL → RECON → SURFACE → HUNT → DEEPTHINK → EXPLOIT → SEARCH → CAPTURE → VALIDATE → REPORT.

- Use `--phase <N>` to run only up to a specific phase
- Use `--resume` to continue from last checkpoint

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success — all phases passed |
| 1 | Generic failure |
| 2 | Triage gate FAILED — finding rejected |
| 3 | Phase gate FAILED — quality gate not met |
| 4 | Target out of scope |
| 5 | Configuration error |

## Environment

| Variable | Default | Description |
|---|---|---|
| `BUGHUNT_OUTPUT` | `~/.bughunt/output/` | Output directory |
| `BUGHUNT_BURP_PROXY` | `http://127.0.0.1:8080` | Burp proxy URL |
| `BUGHUNT_CONCURRENCY` | `10` | Parallel task count |
| `BUGHUNT_TIMEOUT` | `30` | Request timeout in seconds |
