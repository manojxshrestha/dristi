# Tab Mode — Agent Switching

In OpenCode, pressing **Tab** cycles through **primary agents**. Only agents with `mode: all` or `mode: primary` appear in the Tab switcher.

## The Problem

All 14 pipeline agents had `mode: subagent`, which hides them from Tab. Only the two built-in agents (`plan`, `build`) were visible.

## The Fix

Changed `mode: subagent` → `mode: all` in 12 existing agent files, and created 2 missing ones (`auth.md`, `osint.md`) with `mode: all`.

If no `mode` is specified, OpenCode defaults to `all`.

## Agents Changed

| Agent | File | Change |
|-------|------|--------|
| scope | `.opencode/agents/scope.md` | `subagent` → `all` |
| auth | `.opencode/agents/auth.md` | **Created** with `mode: all` |
| osint | `.opencode/agents/osint.md` | **Created** with `mode: all` |
| recon | `.opencode/agents/recon.md` | `subagent` → `all` |
| surface | `.opencode/agents/surface.md` | `subagent` → `all` |
| hunt | `.opencode/agents/hunt.md` | `subagent` → `all` |
| deepthink | `.opencode/agents/deepthink.md` | `subagent` → `all` |
| exploit | `.opencode/agents/exploit.md` | `subagent` → `all` |
| search | `.opencode/agents/search.md` | `subagent` → `all` |
| capture | `.opencode/agents/capture.md` | `subagent` → `all` |
| validate | `.opencode/agents/validate.md` | `subagent` → `all` |
| report | `.opencode/agents/report.md` | `subagent` → `all` |
| autopilot | `.opencode/agents/autopilot.md` | `subagent` → `all` |
| consult | `.opencode/agents/consult.md` | `subagent` → `all` |

## How Tab Works

- **Tab** cycles through agents with `mode: all` or `mode: primary`
- **@name** invokes any agent (including `mode: subagent`)
- `mode: all` = shows in **both** Tab and @-mention
- `mode: subagent` = @-mention only (hidden from Tab)
- `mode: primary` = Tab only

Specialized hunt agents (xss-hunter, sqli-hunter, etc.) remain `mode: subagent` — they're invoked automatically by pipeline agents or with `@name`, not cycled in Tab.
