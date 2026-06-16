# Coverage Matrix — Agent Dispatch Tracking

The coverage matrix is a CSV file at `engagements/<domain>/hunt/coverage_matrix.csv` that tracks which hunt-* agents were dispatched, their results, and their status for gate enforcement and resume.

## Format

```
agent,category,priority,dispatched,findings,targets_tested,status
hunt-xss,input-validation,mandatory,yes,3,12,complete
hunt-sqli,input-validation,mandatory,,,pending
hunt-ssrf,server-side,mandatory,yes,0,8,failed
hunt-nextjs,framework,tech-stack-match,,,skipped
```

## States

| State | Meaning | Gate Treatment | Resume Treatment |
|-------|---------|----------------|------------------|
| `pending` | Not yet dispatched | Counts against threshold | Re-dispatch |
| `complete` | Agent finished, findings recorded | Counts toward threshold | Skip (already done) |
| `failed` | Agent errored or timed out | Counts toward threshold | Re-dispatch (different approach) |
| `skipped` | Agent not applicable (e.g. tech-stack not matching) | Counts toward threshold | Skip (permanently) |

## Gate Threshold

- Phase 6 gate passes when: `(complete + failed + skipped) / total >= 0.9`
- `pending` agents are the only ones that count against passing
- `failed` agents are counted as "tried" but should be noted in the report

## Resume Workflow

When a Phase 6 run is interrupted (timeout, token limit, API error):

1. Read `coverage_matrix.csv`
2. Identify agents with `status = pending` or `status = failed`
3. Only dispatch those agents
4. Do NOT re-dispatch `status = complete` or `status = skipped` agents

## Script Support

```bash
# Generate fresh coverage matrix from dispatch_list.json
bash scripts/coverage_matrix.sh generate <domain>

# View current coverage summary
bash scripts/coverage_matrix.sh status <domain>

# Resume — list pending+failed agents
bash scripts/coverage_matrix.sh resume <domain>

# Mark an agent as complete with findings
bash scripts/coverage_matrix.sh update <domain> <agent-id> complete --findings 3 --targets 12
```
